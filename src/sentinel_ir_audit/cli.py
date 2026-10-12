"""Offline command-line scanner; output contains no raw process command lines."""

import argparse
from collections import Counter
import json
from pathlib import Path
import sys

from . import __version__
from .analyzer import analyze
from .schema import ObservationError, parse_observation

MAX_LINE_BYTES = 128 * 1024
MAX_RECORDS = 50_000
SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


class ScanError(Exception):
    """User-facing failure for invalid input or unsafe output paths."""


def _ensure_paths(input_path: Path, output_path: Path, summary_path: Path | None, overwrite: bool) -> None:
    targets = [input_path.resolve(), output_path.resolve()]
    if summary_path is not None:
        targets.append(summary_path.resolve())
    if len(set(targets)) != len(targets):
        raise ScanError("input, findings, and summary paths must be different")
    if not input_path.is_file():
        raise ScanError("input file does not exist or is not a regular file")
    if not overwrite and (output_path.exists() or (summary_path is not None and summary_path.exists())):
        raise ScanError("output already exists; choose a new path or pass --overwrite")


def scan(input_path: Path) -> tuple[list[dict[str, object]], dict[str, object]]:
    findings: list[dict[str, object]] = []
    record_count = 0
    try:
        with input_path.open("rb") as source:
            for physical_line, raw in enumerate(source, start=1):
                if len(raw) > MAX_LINE_BYTES:
                    raise ScanError(f"line {physical_line}: exceeds {MAX_LINE_BYTES} bytes")
                if not raw.strip():
                    continue
                if record_count >= MAX_RECORDS:
                    raise ScanError(f"more than {MAX_RECORDS} records")
                try:
                    item = json.loads(raw)
                    observation = parse_observation(item, physical_line)
                except (ValueError, UnicodeError, ObservationError) as exc:
                    # Do not echo raw input (potentially contains secrets).
                    raise ScanError(f"line {physical_line}: invalid observation ({type(exc).__name__})") from exc
                record_count += 1
                findings.extend(f.to_jsonable() for f in analyze(observation))
    except OSError as exc:
        raise ScanError(f"could not read input ({type(exc).__name__})") from exc

    counts = Counter(f["severity"] for f in findings)
    summary: dict[str, object] = {
        "tool": "sentinel-ir-audit", "tool_version": __version__,
        "observations": record_count, "findings": len(findings),
        "severity_counts": {key: counts.get(key, 0) for key in SEVERITY_RANK},
        "disclaimer": "Heuristic triage only; a finding does not establish compromise.",
    }
    return findings, summary


def _write_json(path: Path, objects: list[dict[str, object]] | dict[str, object], jsonl: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    # Writes are performed only after all input passes validation.
    with path.open("w", encoding="utf-8", newline="\n") as result:
        if jsonl:
            for item in objects:
                result.write(json.dumps(item, ensure_ascii=False, sort_keys=True) + "\n")
        else:
            json.dump(objects, result, ensure_ascii=False, indent=2, sort_keys=True)
            result.write("\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sentinel-ir-audit", description="Offline, read-only security triage of JSONL observations")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="action", required=True)
    check = sub.add_parser("scan", help="analyze a locally stored JSONL snapshot")
    check.add_argument("--input", type=Path, required=True)
    check.add_argument("--output", type=Path, required=True, help="JSONL findings output")
    check.add_argument("--summary", type=Path, help="optional JSON summary output")
    check.add_argument("--overwrite", action="store_true", help="allow replacing existing output reports")
    check.add_argument("--fail-on", choices=("none", *SEVERITY_RANK), default="none", help="exit 3 if findings at/above severity (default: none)")
    args = parser.parse_args(argv)
    try:
        _ensure_paths(args.input, args.output, args.summary, args.overwrite)
        findings, summary = scan(args.input)
        _write_json(args.output, findings, jsonl=True)
        if args.summary:
            _write_json(args.summary, summary, jsonl=False)
    except (OSError, ScanError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    print(json.dumps(summary, sort_keys=True))
    if args.fail_on != "none" and any(SEVERITY_RANK[str(f["severity"])] >= SEVERITY_RANK[args.fail_on] for f in findings):
        return 3
    return 0
