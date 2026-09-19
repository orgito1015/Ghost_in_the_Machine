"""
ghost.core.engine
====================

GhostEngine is the orchestrator: given an ApplicationSpec, it
- builds the StateGraph,
- walks legal paths to establish realistic baselines and chain values,
- fires illegal transitions (single-hop by default; see `scan()`),
- routes each response through the detection layer instead of a
  string-match heuristic, and
- emits structured Finding objects for the reporting layer.

This replaces v1's single linear script (`__main__` doing everything)
with a reusable, testable class.
"""

from __future__ import annotations

import logging
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Sequence

import httpx

from ghost.core.chaining import extract_values, render_template
from ghost.core.checkpoint import save_checkpoint
from ghost.core.http import request_with_retry
from ghost.core.session import SessionContext, SessionPool
from ghost.core.state_graph import IllegalEdge, IllegalSequence, StateGraph
from ghost.detection.baseline import BaselineFingerprint, fingerprint_blocked_response
from ghost.detection.diff import AnomalyVerdict, classify_anomaly
from ghost.detection.mass_assignment import DEFAULT_CANDIDATE_FIELDS, reflected_fields
from ghost.detection.race import RaceComparator
from ghost.detection.race import evaluate as evaluate_race
from ghost.detection.scorer import Finding, Severity, score_finding
from ghost.detection.session_diff import describe as describe_session_diff
from ghost.detection.session_diff import diff_responses, json_body
from ghost.detection.timing import sample_blocked_latency
from ghost.spec.schema import ApplicationSpec, StateDefinition


@dataclass
class EngineConfig:
    request_timeout: float = 15.0
    delay_between_requests: float = 0.0  # politeness throttle for the target
    http2: bool = True
    timing_baseline_samples: int = 3  # 0 disables timing-based detection
    max_sequence_length: int = 3  # cap for opt-in multi-hop illegal sequences
    max_retries: int = 3  # transient httpx.TransportError / 429 retries
    retry_backoff_base: float = 0.5
    race_concurrency: int = 10  # concurrent requests fired by probe_race_condition
    dry_run: bool = False  # log what a probe would send instead of sending it (--dry-run)
    allow_destructive: bool = False  # required to probe a `destructive: true` state (--i-know-what-im-doing)


logger = logging.getLogger("ghost.engine")


class ProbeSkipped(RuntimeError):
    """Raised instead of firing a request when the engine deliberately
    withholds a probe: dry-run mode, or a `destructive: true` state
    without explicit operator opt-in (see docs/ethics.md). Caught by
    `scan()`'s per-edge/-sequence loop (recorded in `ScanResult.skipped`,
    not treated as a scan failure) and by the CLI's single-probe
    commands (logged, no request sent).

    Only raised by probes the engine launches on its own initiative
    (illegal transition/sequence, race, replay, mass-assignment) — not
    by `execute_step`, since warm-up states are an explicit operator
    choice, not the fuzzer guessing.
    """


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    attempted_edges: int = 0
    errors: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)  # ProbeSkipped reasons (dry-run / destructive guard)


class GhostEngine:
    def __init__(self, spec: ApplicationSpec, config: EngineConfig | None = None):
        self.spec = spec
        self.graph = StateGraph(spec)
        self.config = config or EngineConfig()
        self.client = httpx.Client(http2=self.config.http2, timeout=self.config.request_timeout)
        self.sessions = SessionPool()
        self._baseline_cache: dict[str, BaselineFingerprint] = {}
        self._timing_cache: dict[str, float] = {}

    # -- legitimate path execution -------------------------------------------------

    def execute_step(
        self, step_name: str, session: SessionContext, payload_override: dict | None = None
    ) -> httpx.Response:
        """Execute a state along its intended, legal path — used both
        to establish a starting baseline and to extract chained values
        before attempting an illegal jump from that point.
        """
        state = self._require_state(step_name)
        data = {**state.default_data, **(payload_override or {})}
        data = render_template(data, session.extracted)

        response = self._fire(state, session, data)

        if response.status_code == 401 and session.refresh_token():
            logger.info("401 on legitimate step '%s' — refreshed bearer token, retrying once", step_name)
            response = self._fire(state, session, data)

        session.absorb_response(response)

        if state.extract:
            session.extracted.update(extract_values(response, state.extract))

        self._throttle()
        return response

    # -- illegal transition attempts -----------------------------------------------

    def inject_illegal_transition(
        self, edge: IllegalEdge, session: SessionContext
    ) -> Finding:
        """Attempt one illegal transition and classify the result.

        Unlike v1, this:
          - carries the actor's real session (cookies/headers) forward,
          - fills the target state's templated fields from any values
            already extracted in this session,
          - compares the response against a per-state "known blocked"
            baseline rather than a naive string match.
        """
        target = self._require_state(edge.to_state)
        self._guard(edge.to_state, target)
        baseline = self._get_baseline(edge.to_state, target)
        baseline_elapsed = self._get_timing_baseline(edge.to_state, target)

        data = render_template(target.default_data, session.extracted)
        session.apply_to_client(self.client)

        start = time.monotonic()
        response = request_with_retry(
            self.client,
            target.method.value,
            target.url,
            json=data,
            headers={
                **target.headers,
                **session.request_headers(),
                "X-Sequence-State": edge.from_state,
            },
            max_retries=self.config.max_retries,
            backoff_base=self.config.retry_backoff_base,
        )
        elapsed = time.monotonic() - start
        self._throttle()

        # Carry the session forward even on an illegal probe: a bypass that
        # sets a cookie or returns a chainable value should be usable by a
        # later hop (see inject_illegal_sequence) exactly like a legal step.
        session.absorb_response(response)
        if target.extract:
            try:
                session.extracted.update(extract_values(response, target.extract))
            except ValueError:
                pass  # a blocked/rejected response often won't match the expected shape

        anomaly = classify_anomaly(
            response, baseline, elapsed_seconds=elapsed, baseline_elapsed_seconds=baseline_elapsed
        )
        return score_finding(edge, response, anomaly)

    def inject_illegal_sequence(self, sequence: IllegalSequence, session: SessionContext) -> list[Finding]:
        """Attempt a chained walk of illegal hops in one continuous
        session, testing whether bypasses compound — e.g. after an
        illegal skip to state B exposes a value, use it to also
        illegally skip to state D.

        Stops early (returning findings collected so far) if a hop's
        target needs a templated value no earlier hop produced —
        the multi-hop equivalent of a required extraction aborting
        the chain.
        """
        findings: list[Finding] = []
        for hop in sequence.hops:
            try:
                findings.append(self.inject_illegal_transition(hop, session))
            except KeyError:
                break
        return findings

    # -- additional bug classes ------------------------------------------------------
    #
    # These probes don't fit the state-graph's illegal-transition model (they don't
    # attempt an unauthorized state jump), so they build their own `IllegalEdge` as a
    # self-loop or synthetic descriptor and reuse the existing `Finding` shape via
    # `_probe_finding` rather than adding a parallel result type / reporting path.

    def probe_race_condition(
        self,
        state_name: str,
        session: SessionContext,
        *,
        concurrency: int | None = None,
        comparator: RaceComparator | None = None,
    ) -> Finding:
        """Fire `concurrency` copies of `state_name`'s request at once and
        check whether the backend processed a single-use action more than
        once — a TOCTOU race (redeem a coupon twice, double-spend a
        balance) a strictly sequential fuzzer can never see.
        """
        state = self._require_state(state_name)
        self._guard(state_name, state)
        concurrency = concurrency or self.config.race_concurrency

        data = render_template(state.default_data, session.extracted)
        session.apply_to_client(self.client)
        headers = {**state.headers, **session.request_headers()}

        with ThreadPoolExecutor(max_workers=concurrency) as pool:
            futures = [
                pool.submit(
                    request_with_retry,
                    self.client,
                    state.method.value,
                    state.url,
                    json=data,
                    headers=headers,
                    max_retries=self.config.max_retries,
                    backoff_base=self.config.retry_backoff_base,
                )
                for _ in range(concurrency)
            ]
            responses = [f.result() for f in futures]

        result = evaluate_race(responses, comparator)
        edge = IllegalEdge(state_name, state_name, "race-condition probe (concurrent identical requests)")
        return self._probe_finding(edge, responses[0] if responses else None, result.flagged, result.detail)

    def probe_replay(
        self,
        state_name: str,
        session: SessionContext,
        *,
        times: int = 3,
        comparator: RaceComparator | None = None,
    ) -> Finding:
        """Resend a legal step's exact request `times` times, sequentially,
        and flag signs of reprocessing (a resource created again, a
        counter incrementing) — idempotency/replay testing. Sequential,
        not simultaneous, so it catches a different bug shape than
        `probe_race_condition`: a backend with no replay/idempotency-key
        protection at all, rather than one that's merely not race-safe.
        Shares the "was this processed more than once" comparator with
        the race probe instead of duplicating that judgment call.
        """
        state = self._require_state(state_name)
        self._guard(state_name, state)

        data = render_template(state.default_data, session.extracted)
        responses = [self._fire(state, session, data) for _ in range(times)]

        result = evaluate_race(responses, comparator)
        edge = IllegalEdge(state_name, state_name, "replay probe (resent legal request)")
        return self._probe_finding(edge, responses[0] if responses else None, result.flagged, result.detail)

    def diff_across_sessions(
        self, state_name: str, session_a: SessionContext, session_b: SessionContext
    ) -> Finding:
        """Execute a legal state as two different actors and structurally
        diff the JSON response bodies. Not gated by the destructive guard:
        it only executes a *legal* state, exactly like `execute_step`
        during warm-up — the bug this catches is response leakage, not
        reachability, so both sessions are, by definition, allowed here.
        """
        state = self._require_state(state_name)
        data_a = render_template(state.default_data, session_a.extracted)
        data_b = render_template(state.default_data, session_b.extracted)

        response_a = self._fire(state, session_a, data_a)
        response_b = self._fire(state, session_b, data_b)

        diff = diff_responses(response_a, response_b)
        detail = describe_session_diff(diff, session_a.label, session_b.label)
        edge = IllegalEdge(
            f"{state_name} (as {session_a.label})",
            f"{state_name} (as {session_b.label})",
            "cross-session response diff",
        )
        return self._probe_finding(edge, response_a, diff.flagged, detail)

    def probe_mass_assignment(
        self,
        state_name: str,
        session: SessionContext,
        candidate_fields: dict[str, Any] | Sequence[str] | None = None,
    ) -> Finding:
        """Inject fields not present in the state's declared `default_data`
        (privilege/pricing field names by default) into an otherwise-legal
        request and check whether the response reflects the injected
        value back — evidence the backend blindly bound extra
        client-supplied fields onto a model it shouldn't have.
        """
        state = self._require_state(state_name)
        self._guard(state_name, state)

        if candidate_fields is None:
            injected: dict[str, Any] = {name: True for name in DEFAULT_CANDIDATE_FIELDS}
        elif isinstance(candidate_fields, dict):
            injected = dict(candidate_fields)
        else:
            injected = {name: True for name in candidate_fields}

        data = render_template({**state.default_data, **injected}, session.extracted)
        response = self._fire(state, session, data)
        reflected = reflected_fields(injected, json_body(response))

        flagged = bool(reflected)
        detail = (
            f"Injected field(s) reflected back unchanged: {sorted(reflected)} — target likely bound "
            f"extra client-supplied fields onto its model."
            if flagged
            else f"None of the {len(injected)} injected field(s) were reflected back."
        )
        edge = IllegalEdge(state_name, state_name, f"mass-assignment probe (fields: {', '.join(sorted(injected))})")
        return self._probe_finding(edge, response, flagged, detail)

    # -- high-level scan orchestration -----------------------------------------------

    def scan(
        self,
        *,
        actor_label: str = "default",
        target_edges: list[IllegalEdge] | None = None,
        target_sequences: list[IllegalSequence] | None = None,
        warm_up_states: list[str] | None = None,
        multi_hop: bool = False,
        seed_result: ScanResult | None = None,
        resume_from: int = 0,
        checkpoint_path: str | Path | None = None,
        checkpoint_every: int = 25,
    ) -> ScanResult:
        """Run a full scan for one actor.

        `warm_up_states` are executed legitimately first (in order) so
        the session is authenticated and any values they extract are
        available for templating into illegal-transition targets.
        `target_edges` defaults to `graph.high_value_targets()` (auth-
        boundary crossings) — pass `graph.illegal_edges()` for the full
        exhaustive sweep instead.

        `multi_hop=True` switches to the opt-in chained-sequence mode
        (see `StateGraph.illegal_sequences` / `inject_illegal_sequence`)
        instead of single-hop illegal edges; `target_sequences` defaults
        to `graph.illegal_sequences(max_sequence_length=config.max_sequence_length)`.

        Any state with `idempotency_expected: true` in the spec is
        automatically race-probed too (see `probe_race_condition`) —
        that's what "enabled by default" means for that flag; no extra
        opt-in needed once the spec declares it.

        Resumable scans: pass `checkpoint_path` to write progress to a
        JSON file every `checkpoint_every` attempted edges/sequences
        (see ghost.core.checkpoint). To resume, load that file with
        `ghost.core.checkpoint.load_checkpoint`, restore the session
        with `restore_session`, and pass `seed_result=restore_result(...)`
        and `resume_from=checkpoint["completed"]` — `ghost scan --resume`
        does exactly this. Warm-up is skipped when `resume_from > 0`
        (the session was already established before the interruption).
        """
        session = self.sessions.get_or_create(actor_label)
        result = seed_result if seed_result is not None else ScanResult()

        if resume_from == 0:
            for step in warm_up_states or []:
                try:
                    self.execute_step(step, session)
                except Exception as exc:  # noqa: BLE001 - collected, not fatal to the scan
                    result.errors.append(f"warm-up step '{step}' failed: {exc}")

        if multi_hop:
            sequences = (
                target_sequences
                if target_sequences is not None
                else self.graph.illegal_sequences(max_sequence_length=self.config.max_sequence_length)
            )
            for i, sequence in enumerate(sequences):
                if i < resume_from:
                    continue
                result.attempted_edges += len(sequence.hops)
                try:
                    findings = self.inject_illegal_sequence(sequence, session)
                    result.findings.extend(f for f in findings if f.is_notable)
                except ProbeSkipped as exc:
                    result.skipped.append(f"sequence {' -> '.join(sequence.states)}: {exc}")
                except Exception as exc:  # noqa: BLE001
                    result.errors.append(f"sequence {' -> '.join(sequence.states)} failed: {exc}")
                self._maybe_checkpoint(checkpoint_path, actor_label, "sequences", i + 1, checkpoint_every, result, session)
            self._maybe_checkpoint(checkpoint_path, actor_label, "sequences", len(sequences), 1, result, session)
        else:
            edges = target_edges if target_edges is not None else self.graph.high_value_targets()
            for i, edge in enumerate(edges):
                if i < resume_from:
                    continue
                result.attempted_edges += 1
                try:
                    finding = self.inject_illegal_transition(edge, session)
                    if finding.is_notable:
                        result.findings.append(finding)
                except ProbeSkipped as exc:
                    result.skipped.append(f"edge {edge.from_state}->{edge.to_state}: {exc}")
                except Exception as exc:  # noqa: BLE001
                    result.errors.append(f"edge {edge.from_state}->{edge.to_state} failed: {exc}")
                self._maybe_checkpoint(checkpoint_path, actor_label, "edges", i + 1, checkpoint_every, result, session)
            self._maybe_checkpoint(checkpoint_path, actor_label, "edges", len(edges), 1, result, session)

        for state_name, state in self.spec.states.items():
            if not state.idempotency_expected:
                continue
            result.attempted_edges += 1
            try:
                finding = self.probe_race_condition(state_name, session)
                if finding.is_notable:
                    result.findings.append(finding)
            except ProbeSkipped as exc:
                result.skipped.append(f"race probe on '{state_name}': {exc}")
            except Exception as exc:  # noqa: BLE001
                result.errors.append(f"race probe on '{state_name}' failed: {exc}")

        return result

    # -- internals --------------------------------------------------------------

    def _fire(self, state: StateDefinition, session: SessionContext, data: dict) -> httpx.Response:
        session.apply_to_client(self.client)
        return request_with_retry(
            self.client,
            state.method.value,
            state.url,
            json=data,
            headers={**state.headers, **session.request_headers()},
            max_retries=self.config.max_retries,
            backoff_base=self.config.retry_backoff_base,
        )

    def _maybe_checkpoint(
        self,
        checkpoint_path: str | Path | None,
        actor_label: str,
        mode: str,
        completed: int,
        every: int,
        result: ScanResult,
        session: SessionContext,
    ) -> None:
        if checkpoint_path and completed % every == 0:
            save_checkpoint(
                checkpoint_path, actor_label=actor_label, mode=mode, completed=completed, result=result, session=session
            )

    def _require_state(self, name: str) -> StateDefinition:
        state = self.spec.states.get(name)
        if state is None:
            raise KeyError(f"Unknown state '{name}' — not defined in spec '{self.spec.name}'")
        return state

    def _guard(self, state_name: str, state: StateDefinition) -> None:
        """Raise ProbeSkipped instead of letting a probe fire a request,
        for dry-run mode or an unopted-in destructive state. See the
        ProbeSkipped docstring for exactly which call sites use this.
        """
        if self.config.dry_run:
            raise ProbeSkipped(
                f"[dry-run] would fire {state.method.value} {state.url} for '{state_name}' — no request sent."
            )
        if state.destructive and not self.config.allow_destructive:
            raise ProbeSkipped(
                f"'{state_name}' is marked destructive in the spec — refusing to probe it without "
                f"--i-know-what-im-doing (EngineConfig.allow_destructive). See docs/ethics.md."
            )

    def _probe_finding(
        self, edge: IllegalEdge, sample_response: httpx.Response | None, flagged: bool, detail: str
    ) -> Finding:
        """Shared Finding construction for the non-transition probes
        (race/replay/mass-assignment/session-diff) — reuses the existing
        Finding/AnomalyVerdict shape instead of adding a parallel result
        type, so these show up in the existing HTML/JSON reporters
        unmodified. `flagged` picks the closest existing verdict; the
        probe-specific detail lives in the free-text `detail` field.
        """
        return Finding(
            edge=edge,
            verdict=AnomalyVerdict.LIKELY_BYPASS if flagged else AnomalyVerdict.CLEANLY_BLOCKED,
            detail=detail,
            severity=Severity.HIGH if flagged else Severity.INFO,
            status_code=sample_response.status_code if sample_response is not None else 0,
            response_snippet=sample_response.text[:300] if sample_response is not None else "",
            is_notable=flagged,
        )

    def _get_baseline(self, state_name: str, state: StateDefinition) -> BaselineFingerprint:
        if state_name not in self._baseline_cache:
            self._baseline_cache[state_name] = fingerprint_blocked_response(self.client, state)
        return self._baseline_cache[state_name]

    def _get_timing_baseline(self, state_name: str, state: StateDefinition) -> float | None:
        if self.config.timing_baseline_samples <= 0:
            return None
        if state_name not in self._timing_cache:
            self._timing_cache[state_name] = sample_blocked_latency(
                self.client, state, samples=self.config.timing_baseline_samples
            )
        return self._timing_cache[state_name]

    def _throttle(self) -> None:
        if self.config.delay_between_requests:
            time.sleep(self.config.delay_between_requests)

    def close(self) -> None:
        self.client.close()

    def __enter__(self) -> "GhostEngine":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()
