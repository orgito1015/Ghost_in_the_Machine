# Architecture

```
                 ┌─────────────────┐
   spec file --> │  spec.loader     │ --> ApplicationSpec (pydantic)
 (or importer)   └─────────────────┘
                          │
                          v
                 ┌─────────────────┐
                 │  StateGraph      │  legal edges (declared) +
                 │                  │  illegal edges (computed complement,
                 │                  │  auth-boundary crossings prioritized)
                 └─────────────────┘
                          │
                          v
   ┌───────────────────────────────────────────┐
   │              GhostEngine                    │
   │                                              │
   │  execute_step()          inject_illegal_     │
   │   - legal path walk       transition()       │
   │   - SessionContext        - carries session   │
   │     cookies/headers         forward            │
   │   - ExtractionRule       - templates target    │
   │     -> session.extracted    default_data from  │
   │                              session.extracted  │
   └───────────────────────────────────────────┘
                          │
                          v
            ┌───────────────────────────┐
            │      detection layer        │
            │  baseline.py: fingerprint    │
            │    "known blocked" response  │
            │  diff.py: classify_anomaly   │
            │    (status/shape diff +      │
            │     timing signal)           │
            │  scorer.py: Finding +        │
            │    Severity                  │
            └───────────────────────────┘
                          │
                          v
                 ┌─────────────────┐
                 │   ScanResult     │
                 └─────────────────┘
                          │
                          v
              reporting/html_report.py
              reporting/json_report.py
```

## Key design decisions

**Illegal edges are computed, not hand-picked.** `StateGraph` takes
the declared legal `transitions` and computes every other (from, to)
pair over the state set as the candidate attack surface. This means
adding a new state to a spec automatically extends scan coverage
without the operator manually enumerating attacks against it.

**Detection is baseline-relative, not string-matching.** Every target
state gets a one-time "known blocked" fingerprint (a deliberately
unauthorized request) before it's used as an illegal-transition
target. Anomaly classification compares the real attempt's status code
and JSON top-level key shape against that fingerprint. This scales
across arbitrary target applications instead of hardcoding assumptions
about what a rejection looks like.

**Sessions are first-class and poolable.** `SessionPool` supports
multiple named actors (`low_priv_user`, `admin_user`, `anonymous`) so
cross-role attacks — "use user A's session to reach a state scoped to
user B" — are a natural extension, not a rewrite.

**Specs can be authored or imported.** `spec/importers/` is the
extension point for bootstrapping specs from OpenAPI docs or captured
proxy traffic instead of requiring every state to be hand-written.
Imported specs are always drafts — the legal `transitions` graph in
particular needs a human pass, since intended business-flow order
isn't fully recoverable from a schema or from a single traffic
capture.

## v2.1 additions

- `detection/timing.py`'s multi-sample median baseline is wired into
  `GhostEngine._get_baseline`-adjacent `_get_timing_baseline`, cached
  per state alongside the shape fingerprint. Disable with
  `EngineConfig.timing_baseline_samples = 0`.
- `spec/importers/burp_proxy.py` implements Burp "Save items" XML
  import: path templating, Authorization/Cookie redaction, and a
  draft `transitions` list inferred from per-session request order.
- `spec/importers/postman.py` bootstraps a draft spec from a Postman
  collection (v2.x), following the OpenAPI importer's pattern.
- Multi-hop illegal sequences (`StateGraph.illegal_sequences` /
  `GhostEngine.inject_illegal_sequence`, `scan(multi_hop=True)`):
  chained walks where every consecutive hop is illegal, e.g. skip step
  2 AND step 4 in one session. Opt-in and capped via
  `EngineConfig.max_sequence_length` — it's a permutation search
  (O(n!)), materially larger than the single-hop O(n^2) sweep.
- Retry/backoff for transient `httpx.TransportError` and 429
  (`ghost/core/http.py`), a token-refresh hook on `SessionContext` for
  bearer-auth flows, and structured `logging` (`--verbose`) in place
  of `cli.py`'s old print statements.

## v2.2 additions

**Four bug classes beyond illegal-transition testing**, each reusing
the existing `Finding`/`IllegalEdge`/`AnomalyVerdict` shape instead of
adding a parallel result type (see `GhostEngine._probe_finding` — a
non-transition probe gets a synthetic self-loop `IllegalEdge`, with
probe-specific detail in the free-text `detail` field):

- `probe_race_condition` / `probe_replay` (`detection/race.py`): fire
  the same request concurrently (`ThreadPoolExecutor`, since
  `httpx.Client` is safe to share across threads and the rest of this
  codebase is entirely sync) or sequentially, and flag more than one
  success where a single-use action should process at most once. Share
  one comparator. `StateDefinition.idempotency_expected: true` makes
  `scan()` auto-run the race probe for that state — no extra opt-in.
- `diff_across_sessions` (`detection/session_diff.py`): shallow,
  top-level-only diff of two sessions' responses to the same *legal*
  state — catches cross-user data leakage that illegal-transition
  testing can't (both sessions are allowed to reach the state; the bug
  is what each response contains).
- `probe_mass_assignment` (`detection/mass_assignment.py`): injects
  fields absent from a state's declared `default_data` (privilege/
  pricing names by default) and checks whether they're reflected back.

**Safety: `destructive: true` + `--dry-run` / `--i-know-what-im-doing`.**
`GhostEngine._guard` raises `ProbeSkipped` (caught by `scan()` into
`ScanResult.skipped`, not `errors`) before any probe launched on the
engine's own initiative fires at a spec-marked-destructive state,
unless explicitly allowed. See `docs/ethics.md`.

**Coverage:** `spec/importers/graphql.py` (SDL + introspection —
needed no schema change: a GraphQL operation is just a POST with a
`{query, variables}` JSON body, which `StateDefinition.default_data`
already represents) and `spec/importers/record.py` (`ghost record`:
live capture via an optional mitmproxy dependency, sharing
`spec/importers/traffic_capture.py`'s grouping/templating/redaction/
transition-inference with `burp_proxy.py` instead of duplicating it).

**Operations:** resumable `--full`/`--multi-hop` scans
(`ghost/core/checkpoint.py`, `scan(checkpoint_path=..., resume_from=...)`,
`ghost scan --resume`), `ghost diff` for new/resolved/persistent
findings between two JSON reports (`reporting/report_diff.py`), and
`ghost scan --fail-on SEVERITY` for CI gating (default: always exit 0,
unchanged for existing callers).
