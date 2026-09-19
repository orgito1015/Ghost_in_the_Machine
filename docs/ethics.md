# Authorized Use Only

Ghost In The Machine is a business-logic fuzzing tool for security
engagements you are explicitly authorized to perform (e.g. a signed
pentest/red-team engagement, a bug bounty program's defined scope, or
your own infrastructure).

Before running a scan against any target:

- Confirm written authorization / a signed scope covers the specific
  hosts and endpoints in your spec's `base_url` and `states`.
- Respect the engagement's rate limits — use `EngineConfig.delay_between_requests`
  or `--delay` to throttle.
- Be aware that `inject_illegal_transition` targeting `ADMIN_REFUND`-style
  states (or any state that performs a real write — refunds, deletions,
  privilege grants) can have real, hard-to-reverse effects on the
  target's data if the bypass succeeds. Coordinate with the client on
  which states are safe to actually complete vs. which should be
  tested read-only or against a staging environment.
- The race-condition and replay probes (`probe_race_condition`,
  `probe_replay`) are especially dangerous against a write endpoint:
  by design they fire the same request multiple times concurrently or
  in quick succession, so a *successful* finding (a double-processed
  refund, a coupon redeemed twice) means the target's data was just
  actually mutated more than once. Prefer running these against a
  staging environment, or coordinate an explicit rollback plan with
  the client before running them against production.
- Mass-assignment probing (`probe_mass_assignment`) sends real requests
  with extra fields (`is_admin`, `price`, `balance`, etc. by default —
  see `ghost/detection/mass_assignment.py`); a successful bypass may
  leave the target's data in the bypassed state (e.g. an account
  actually flagged admin, a price actually changed).

## Marking destructive states — `destructive: true`

Tag any state that performs a real write with real, hard-to-reverse
effects — refunds, deletions, privilege grants, anything you would not
want a fuzzer sweep hitting by accident — as `"destructive": true` in
the spec (see `StateDefinition.destructive` in `ghost/spec/schema.py`).

By default, **no probe launched on the engine's own initiative**
(`inject_illegal_transition`/`inject_illegal_sequence`,
`probe_race_condition`, `probe_replay`, `probe_mass_assignment`) will
fire a request at a `destructive: true` state — it's skipped and
logged instead (surfaced in `ScanResult.skipped` / the report's
"Skipped" count). This does **not** cover `execute_step` used for
explicit `--warm-up` states or `diff_across_sessions`: those only ever
execute a state the operator or the spec's own legal flow already
named, not a state the fuzzer picked on its own.

- `--dry-run` makes every guarded probe log what it *would* have sent
  instead of sending it — use this first, on any new spec, to see
  which states the scan would actually touch before it touches them.
- `--i-know-what-im-doing` (`EngineConfig.allow_destructive`) lifts the
  destructive-state guard and lets probes fire at those states for
  real. Only pass this once you and the client have explicitly agreed
  which destructive states are safe to actually exercise, and how
  (staging vs. production, rollback plan, notification).

Do not point this tool at systems you do not have explicit permission
to test.
