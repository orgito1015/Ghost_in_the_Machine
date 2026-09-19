"""
ghost.cli
==========

Command-line entrypoint.

Usage:
    ghost scan  --spec specs/example_ecommerce.json --out report.html
    ghost scan  --spec specs/example_ecommerce.json --full --out report.json --format json
    ghost import-openapi --input swagger.json --out specs/draft.json
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from ghost.core.engine import EngineConfig, GhostEngine, ProbeSkipped
from ghost.detection.scorer import Severity
from ghost.reporting.html_report import write_html_report
from ghost.reporting.json_report import write_json_report
from ghost.reporting.models import ReportContext
from ghost.spec.loader import load_spec, save_spec

logger = logging.getLogger("ghost.cli")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ghost", description="Ghost In The Machine — stateful business-logic fuzzer")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable debug-level logging")
    sub = parser.add_subparsers(dest="command", required=True)

    scan_p = sub.add_parser("scan", help="Run a scan against a target spec")
    scan_p.add_argument("--spec", required=True, help="Path to ApplicationSpec JSON/YAML")
    scan_p.add_argument("--out", required=True, help="Report output path")
    scan_p.add_argument("--format", choices=["html", "json"], default="html")
    scan_p.add_argument("--full", action="store_true", help="Exhaustive sweep instead of high-value auth-boundary targets only")
    scan_p.add_argument("--warm-up", nargs="*", default=[], help="States to execute legitimately first, in order")
    scan_p.add_argument("--actor", default="default", help="Session actor label")
    scan_p.add_argument("--delay", type=float, default=0.0, help="Seconds between requests (politeness throttle)")
    scan_p.add_argument(
        "--multi-hop", action="store_true",
        help="Opt-in: attempt chained illegal sequences (skip step 2 AND step 4) instead of single-hop edges. O(n!) — see docs/architecture.md.",
    )
    scan_p.add_argument("--max-sequence-length", type=int, default=3, help="Cap on states per illegal sequence when --multi-hop is set")
    scan_p.add_argument("--dry-run", action="store_true", help="Log what each probe would send instead of sending it")
    scan_p.add_argument(
        "--i-know-what-im-doing", action="store_true", dest="allow_destructive",
        help="Allow probes to target states marked `destructive: true` in the spec. See docs/ethics.md.",
    )
    scan_p.add_argument(
        "--resume", metavar="CHECKPOINT_FILE", default=None,
        help="Checkpoint file, written periodically during the scan. If it already exists at start, "
        "resume from it instead of restarting (useful for a long --full or --multi-hop scan).",
    )
    scan_p.add_argument("--checkpoint-every", type=int, default=25, help="Write --resume's checkpoint file every N attempted edges/sequences")
    scan_p.add_argument(
        "--fail-on", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"], default=None,
        help="Exit non-zero if any finding at or above this severity was produced (CI gate). Default: always exit 0.",
    )

    diff_p = sub.add_parser("diff", help="Compare two JSON scan reports")
    diff_p.add_argument("report_a")
    diff_p.add_argument("report_b")
    diff_p.add_argument("--out", default=None, help="Optional path to also write the diff as its own JSON report")

    race_p = sub.add_parser("race", help="Probe a single state for a race condition via concurrent identical requests")
    race_p.add_argument("--spec", required=True, help="Path to ApplicationSpec JSON/YAML")
    race_p.add_argument("--state", required=True, help="State name to probe")
    race_p.add_argument("--concurrency", type=int, default=10)
    race_p.add_argument("--warm-up", nargs="*", default=[], help="States to execute legitimately first, in order")
    race_p.add_argument("--actor", default="default")
    race_p.add_argument("--dry-run", action="store_true", help="Log what would be sent instead of sending it")
    race_p.add_argument(
        "--i-know-what-im-doing", action="store_true", dest="allow_destructive",
        help="Allow probing a state marked `destructive: true` in the spec. See docs/ethics.md.",
    )

    import_p = sub.add_parser("import-openapi", help="Bootstrap a draft spec from an OpenAPI document")
    import_p.add_argument("--input", required=True)
    import_p.add_argument("--out", required=True)
    import_p.add_argument("--base-url", default=None)

    import_pm_p = sub.add_parser("import-postman", help="Bootstrap a draft spec from a Postman collection")
    import_pm_p.add_argument("--input", required=True)
    import_pm_p.add_argument("--out", required=True)
    import_pm_p.add_argument("--base-url", default=None)

    import_burp_p = sub.add_parser("import-burp", help="Bootstrap a draft spec from a Burp 'Save items' XML export")
    import_burp_p.add_argument("--input", required=True)
    import_burp_p.add_argument("--out", required=True)

    import_gql_p = sub.add_parser("import-graphql", help="Bootstrap a draft spec from a GraphQL SDL document or introspection result")
    import_gql_p.add_argument("--input", required=True)
    import_gql_p.add_argument("--out", required=True)
    import_gql_p.add_argument("--endpoint", required=True, help="The single GraphQL endpoint URL every generated state POSTs to")
    import_gql_p.add_argument("--format", choices=["sdl", "introspection"], default="introspection")

    record_p = sub.add_parser(
        "record",
        help="Run a local MITM proxy, manually walk a legal flow through it once, then bootstrap a draft spec "
        "from what got captured (needs `pip install -e '.[record]'`)",
    )
    record_p.add_argument("--proxy-port", type=int, default=8080)
    record_p.add_argument("--out", required=True)

    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )

    if args.command == "scan":
        return _cmd_scan(args)
    if args.command == "diff":
        return _cmd_diff(args)
    if args.command == "race":
        return _cmd_race(args)
    if args.command == "import-openapi":
        return _cmd_import_openapi(args)
    if args.command == "import-postman":
        return _cmd_import_postman(args)
    if args.command == "import-burp":
        return _cmd_import_burp(args)
    if args.command == "import-graphql":
        return _cmd_import_graphql(args)
    if args.command == "record":
        return _cmd_record(args)

    parser.print_help()
    return 1


def _cmd_scan(args: argparse.Namespace) -> int:
    from ghost.core.checkpoint import load_checkpoint, restore_result, restore_session

    spec = load_spec(args.spec)
    config = EngineConfig(
        delay_between_requests=args.delay,
        max_sequence_length=args.max_sequence_length,
        dry_run=args.dry_run,
        allow_destructive=args.allow_destructive,
    )

    resume_from = 0
    seed_result = None
    checkpoint = None
    if args.resume and Path(args.resume).exists():
        checkpoint = load_checkpoint(args.resume)
        resume_from = checkpoint["completed"]
        seed_result = restore_result(checkpoint)
        logger.info("Resuming from checkpoint %s (%d already attempted)", args.resume, resume_from)

    with GhostEngine(spec, config) as engine:
        if checkpoint is not None:
            restore_session(engine.sessions.get_or_create(args.actor), checkpoint)
        target_edges = engine.graph.illegal_edges() if args.full else None
        result = engine.scan(
            actor_label=args.actor,
            target_edges=target_edges,
            warm_up_states=args.warm_up,
            multi_hop=args.multi_hop,
            seed_result=seed_result,
            resume_from=resume_from,
            checkpoint_path=args.resume,
            checkpoint_every=args.checkpoint_every,
        )

    ctx = ReportContext(target_name=spec.name, scan_result=result)
    if args.format == "html":
        write_html_report(ctx, args.out)
    else:
        write_json_report(ctx, args.out)

    logger.info("%d notable finding(s) across %d attempted edge(s).", len(result.findings), result.attempted_edges)
    logger.info("Report written to %s", args.out)
    if result.skipped:
        logger.info("%d probe(s) skipped (dry-run / destructive guard).", len(result.skipped))
        for note in result.skipped:
            logger.debug("skipped: %s", note)
    if result.errors:
        logger.warning("%d error(s) during scan — report is not exhaustive for these edges.", len(result.errors))
        for err in result.errors:
            logger.debug("scan error: %s", err)

    if args.fail_on is not None:
        threshold = Severity[args.fail_on]
        if any(f.severity >= threshold for f in result.findings):
            logger.error("At least one finding >= %s — failing per --fail-on.", args.fail_on)
            return 1
    return 0


def _cmd_diff(args: argparse.Namespace) -> int:
    from ghost.reporting.report_diff import diff_reports, load_report, render_summary, write_diff_json

    diff = diff_reports(load_report(args.report_a), load_report(args.report_b))
    print(render_summary(diff))
    if args.out:
        write_diff_json(diff, args.out)
        logger.info("Diff written to %s", args.out)
    return 0


def _cmd_race(args: argparse.Namespace) -> int:
    spec = load_spec(args.spec)
    config = EngineConfig(dry_run=args.dry_run, allow_destructive=args.allow_destructive)

    with GhostEngine(spec, config) as engine:
        session = engine.sessions.get_or_create(args.actor)
        for step in args.warm_up:
            engine.execute_step(step, session)
        try:
            finding = engine.probe_race_condition(args.state, session, concurrency=args.concurrency)
        except ProbeSkipped as exc:
            logger.warning("Race probe on '%s' skipped: %s", args.state, exc)
            return 0

    logger.info("Race probe on '%s': %s (severity=%s)", args.state, finding.detail, finding.severity.name)
    return 0


def _cmd_import_openapi(args: argparse.Namespace) -> int:
    import json

    from ghost.spec.importers.openapi import import_openapi

    with open(args.input) as f:
        doc = json.load(f)

    spec = import_openapi(doc, base_url=args.base_url)
    save_spec(spec, args.out)
    logger.info("Draft spec with %d states written to %s", len(spec.states), args.out)
    logger.info("NOTE: transitions, entry_states, and auth_context need manual review before scanning.")
    return 0


def _cmd_import_postman(args: argparse.Namespace) -> int:
    import json

    from ghost.spec.importers.postman import import_postman

    with open(args.input) as f:
        doc = json.load(f)

    spec = import_postman(doc, base_url=args.base_url)
    save_spec(spec, args.out)
    logger.info("Draft spec with %d states written to %s", len(spec.states), args.out)
    logger.info("NOTE: transitions, entry_states, and auth_context need manual review before scanning.")
    return 0


def _cmd_import_burp(args: argparse.Namespace) -> int:
    from ghost.spec.importers.burp_proxy import import_burp_xml

    spec = import_burp_xml(args.input)
    save_spec(spec, args.out)
    logger.info(
        "Draft spec with %d states and %d inferred transition(s) written to %s",
        len(spec.states), len(spec.transitions), args.out,
    )
    logger.info("NOTE: transitions are inferred from observed request order — review before trusting as intended business logic.")
    return 0


def _cmd_import_graphql(args: argparse.Namespace) -> int:
    import json

    from ghost.spec.importers.graphql import import_graphql_introspection, import_graphql_sdl

    with open(args.input) as f:
        raw = f.read()

    if args.format == "introspection":
        spec = import_graphql_introspection(json.loads(raw), endpoint=args.endpoint)
    else:
        spec = import_graphql_sdl(raw, endpoint=args.endpoint)

    save_spec(spec, args.out)
    logger.info("Draft spec with %d states written to %s", len(spec.states), args.out)
    logger.info("NOTE: transitions, entry_states, auth_context, and variable placeholders need manual review before scanning.")
    return 0


def _cmd_record(args: argparse.Namespace) -> int:
    from ghost.spec.importers.record import build_spec_from_recording, run_recording_proxy

    logger.info(
        "Starting recording proxy on 127.0.0.1:%d — point your browser/client at it, walk the legal "
        "flow once, then press Ctrl+C to stop and write the draft spec.",
        args.proxy_port,
    )
    try:
        captures = run_recording_proxy(args.proxy_port)
    except ImportError as exc:
        logger.error(str(exc))
        return 1

    if not captures:
        logger.warning("No requests were captured — nothing written.")
        return 1

    spec = build_spec_from_recording(captures)
    save_spec(spec, args.out)
    logger.info("Draft spec with %d states written to %s", len(spec.states), args.out)
    logger.info("NOTE: transitions, entry_states, and auth_context need manual review before scanning.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
