# Ghost In The Machine

A stateful business-logic fuzzer for authorized security engagements.

Instead of blind input fuzzing, it models an application's behavioral
lifecycle as a **directed graph of states and legal transitions**, then
systematically attempts *illegal* transitions, state-skips,
step-reordering, privilege-boundary jumps,  while carrying real session
context and chained values forward.

> **For authorized use only.** Run this only against systems you are
> explicitly engaged/authorized to test. See `docs/ethics.md`.

## What changed from v1

The original single-file script proved the concept but had five gaps
this rewrite addresses:

| Gap in v1 | Fix in v2 |
|---|---|
| `transitions` loaded but unused; illegal targets picked by hand | `StateGraph` computes illegal edges as the complement of the declared legal graph, with auth-boundary crossings prioritized |
| Cookies captured but never replayed | `SessionContext` / `SessionPool` carry auth state across every request for a simulated actor |
| `"error" not in res.text` string match | `detection/baseline.py` + `diff.py` fingerprint a per-state "known blocked" response and structurally diff against it |
| No cross-step value passing | `core/chaining.py` — `ExtractionRule`s + `{{template}}` substitution |
| Hand-written JSON specs only | `spec/importers/` bootstraps drafts from OpenAPI (implemented) and Burp/ZAP proxy history (stubbed) |

## Project layout

```
ghost_in_the_machine/
├── ghost/
│   ├── core/
│   │   ├── engine.py        # GhostEngine orchestrator
│   │   ├── state_graph.py   # legal/illegal edge computation
│   │   ├── session.py       # auth/cookie continuity per actor
│   │   └── chaining.py      # cross-step value extraction/templating
│   ├── detection/
│   │   ├── baseline.py         # per-state "known blocked" fingerprinting
│   │   ├── diff.py             # structural anomaly classification
│   │   ├── timing.py           # latency-based secondary signal
│   │   ├── scorer.py           # Finding model + severity scoring
│   │   ├── race.py             # race/replay "processed more than once" comparator
│   │   ├── session_diff.py     # cross-session response-body diff (IDOR-by-leakage)
│   │   └── mass_assignment.py  # injected-field reflection check
│   ├── spec/
│   │   ├── schema.py        # pydantic ApplicationSpec model
│   │   ├── loader.py        # JSON/YAML spec loading
│   │   └── importers/
│   │       ├── openapi.py          # OpenAPI/Swagger -> draft spec
│   │       ├── postman.py          # Postman collection -> draft spec
│   │       ├── graphql.py          # GraphQL SDL/introspection -> draft spec
│   │       ├── traffic_capture.py  # shared grouping/templating/redaction, used by burp_proxy.py + record.py
│   │       ├── burp_proxy.py       # Burp XML export -> draft spec (ZAP import still stubbed)
│   │       └── record.py           # `ghost record`'s mitmproxy addon -> draft spec
│   ├── reporting/
│   │   ├── models.py
│   │   ├── html_report.py
│   │   ├── json_report.py
│   │   └── report_diff.py   # `ghost diff` — new/resolved/persistent findings between two runs
│   └── cli.py
├── specs/example_ecommerce.json
├── tests/
└── docs/
    ├── architecture.md
    └── ethics.md
```

## Quick start

```bash
pip install -e ".[dev]"

# Focused scan: auth-boundary-crossing illegal edges only, with a
# legitimate warm-up path first so the session is authenticated.
ghost scan --spec specs/example_ecommerce.json \
           --warm-up LOGIN ADD_TO_CART \
           --out report.html

# Exhaustive sweep of every non-legal state pair, JSON output.
ghost scan --spec specs/example_ecommerce.json --full \
           --format json --out report.json

# Opt-in multi-hop mode: chained illegal sequences (e.g. skip step 2
# AND step 4 in one session), capped at 4 states per walk.
ghost scan --spec specs/example_ecommerce.json --multi-hop \
           --max-sequence-length 4 --out report.html

# Bootstrap a draft spec from an existing OpenAPI doc, Postman
# collection, a Burp "Save items" XML export, or a GraphQL schema.
ghost import-openapi --input swagger.json --out specs/draft.json
ghost import-postman --input collection.json --out specs/draft.json
ghost import-burp --input burp_export.xml --out specs/draft.json
ghost import-graphql --input schema.json --endpoint https://api.example.com/graphql --out specs/draft.json

# Or record a draft spec live: run a local MITM proxy, point a
# browser/client at it, manually walk a legal flow once, Ctrl+C.
ghost record --proxy-port 8080 --out specs/recorded.json

# Probe one state for a race condition (concurrent identical requests).
ghost race --spec specs/example_ecommerce.json --state ADD_TO_CART --concurrency 10

# Resume a long --full/--multi-hop scan that got interrupted.
ghost scan --spec specs/example_ecommerce.json --full --resume checkpoint.json --out report.json --format json

# CI gate: exit non-zero if any HIGH+ finding was produced.
ghost scan --spec specs/example_ecommerce.json --fail-on HIGH --out report.json --format json

# Compare two JSON reports (e.g. before/after a patch).
ghost diff report_before.json report_after.json
```

## Writing a spec

See `specs/example_ecommerce.json` for a full example. Key fields:

- `states` — one entry per endpoint/step, with `auth_context`
  (`anonymous` / `authenticated` / `admin`) and optional `extract`
  rules for chaining values into later steps.
- `transitions` — the **legal** graph. Everything not listed here is
  fair game for `inject_illegal_transition`.
- `entry_states` — valid session starting points.

## Library usage

```python
from ghost.spec.loader import load_spec
from ghost.core.engine import GhostEngine

spec = load_spec("specs/example_ecommerce.json")
with GhostEngine(spec) as engine:
    result = engine.scan(warm_up_states=["LOGIN", "ADD_TO_CART"])
    for finding in result.findings:
        print(finding.severity.name, finding.edge, finding.detail)
```

## Status

v2.2 adds four more bug classes beyond illegal-transition testing —
`GhostEngine.probe_race_condition`, `probe_replay`,
`diff_across_sessions`, `probe_mass_assignment` (see `ghost race` and
`docs/architecture.md`) — plus a `destructive: true` spec flag with a
`--dry-run` / `--i-know-what-im-doing` safety gate (see
`docs/ethics.md`), a GraphQL importer, a live `ghost record` capture
path (mitmproxy, optional `[record]` extra), resumable `--full`/
`--multi-hop` scans (`--resume`), `ghost diff` for comparing two JSON
reports, and `--fail-on` for CI gating. All implemented and tested.

Known gaps: ZAP session import
(`spec/importers/burp_proxy.py:import_zap_session`) remains a stub.
`ghost record`'s mitmproxy proxy lifecycle (`spec/importers/record.py:
run_recording_proxy`) is implemented against the real mitmproxy 12.x
API but hasn't been exercised end-to-end against a live proxied
client in CI — sanity-check it against your installed mitmproxy
version before relying on it for an engagement. Everything else runs
end-to-end against a real spec (the bundled example targets
`httpbin.org` for a safe smoke test).
