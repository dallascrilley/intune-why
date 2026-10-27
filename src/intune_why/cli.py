"""Command-line interface."""

import argparse
import datetime as dt
import json
import os
import sys
import webbrowser
from pathlib import Path

from . import __version__
from .analyze import SnapshotError, analyze
from .classify import classify
from .graph import DEFAULT_CLIENT_ID, GraphClient, GraphError, collect, device_code_token
from .report import redact, to_csv, to_html, to_text

DEMO = Path(__file__).with_name("data") / "demo_snapshot.json"


def _warn(message):
    print("intune-why: " + message, file=sys.stderr)


def _write(path, text, private=False):
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    if private:
        # Snapshots hold tenant data: create them owner-only from the first byte.
        fd = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
        os.chmod(str(target), 0o600)
    else:
        target.write_text(text, encoding="utf-8")
    return target


def _build(snapshot, args):
    report = analyze(snapshot, stale_days=args.stale_days)
    classify(report, decider=args.decide, warn=_warn)
    if getattr(args, "redact", False):
        redact(report)
    return report


def _emit(report, args):
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(to_text(report))
    if args.csv:
        _warn("wrote " + str(_write(args.csv, to_csv(report))))
    if args.html:
        path = _write(args.html, to_html(report))
        _warn("wrote " + str(path))
        if getattr(args, "open", False):
            webbrowser.open(path.resolve().as_uri())


def cmd_demo(args):
    snapshot = json.loads(DEMO.read_text(encoding="utf-8"))
    args.html = args.html or "intune-why-demo.html"
    args.open = not args.no_open
    _emit(_build(snapshot, args), args)
    return 0


def cmd_analyze(args):
    text = sys.stdin.read() if args.snapshot == "-" else Path(args.snapshot).read_text(encoding="utf-8")
    _emit(_build(json.loads(text), args), args)
    return 0


def cmd_collect(args):
    if args.token_stdin:
        token = sys.stdin.readline().strip()
    else:
        token = device_code_token(args.tenant, args.client_id)
    client = GraphClient(token)
    snapshot = collect(client, dt.datetime.now(dt.timezone.utc), progress=_warn)
    if args.tenant:
        snapshot["tenant"] = args.tenant
    out = _write(args.out, json.dumps(snapshot, indent=2), private=True)
    _warn("wrote %s (%d devices, %d failing setting states, %d Graph requests)" % (
        out, len(snapshot["devices"]), len(snapshot["setting_states"]), client.requests))
    args.json = False
    _emit(_build(snapshot, args), args)
    return 0


def _report_options(p):
    p.add_argument("--html", metavar="FILE", help="write the interactive report")
    p.add_argument("--csv", metavar="FILE", help="write every affected device with its root cause")
    p.add_argument("--stale-days", type=int, default=30, help="days without sync before a device counts as stale (default 30)")
    p.add_argument("--decide", choices=("rules", "jev"), default="rules",
                   help="classify unknown settings with built-in rules only, or ask Jev (needs TYPESAFE_API_KEY)")
    p.add_argument("--redact", action="store_true", help="replace device and user names with pseudonyms for sharing")


def parser():
    p = argparse.ArgumentParser(prog="intune-why", description="Find the few fixes that clear most Intune noncompliance.")
    p.add_argument("--version", action="version", version="intune-why " + __version__)
    sub = p.add_subparsers(dest="command", required=True)

    demo = sub.add_parser("demo", help="open the report for a fictional 320-device tenant")
    _report_options(demo)
    demo.add_argument("--json", action="store_true", help="print the full report as JSON")
    demo.add_argument("--no-open", action="store_true", help="write the report without opening a browser")
    demo.set_defaults(func=cmd_demo)

    an = sub.add_parser("analyze", help="analyze a saved snapshot")
    an.add_argument("snapshot", help="snapshot JSON file, or - for stdin")
    _report_options(an)
    an.add_argument("--json", action="store_true", help="print the full report as JSON")
    an.add_argument("--open", action="store_true", help="open the HTML report when written")
    an.set_defaults(func=cmd_analyze)

    co = sub.add_parser("collect", help="read a snapshot from Microsoft Graph (read-only)")
    co.add_argument("--tenant", help="tenant domain or ID for sign-in (default: organizations)")
    co.add_argument("--client-id", default=DEFAULT_CLIENT_ID, help="public client app ID for device code sign-in")
    co.add_argument("--token-stdin", action="store_true", help="read a Graph access token from stdin instead of signing in")
    co.add_argument("--out", default="intune-snapshot.json", help="snapshot file to write (default intune-snapshot.json)")
    _report_options(co)
    co.add_argument("--open", action="store_true", help="open the HTML report when written")
    co.set_defaults(func=cmd_collect, json=False)
    return p


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        return args.func(args)
    except (SnapshotError, GraphError, OSError, ValueError, KeyError) as exc:
        _warn(str(exc) or type(exc).__name__)
        return 1
    except KeyboardInterrupt:
        return 130
