# Sentinel IR Audit

**Offline, read-only Windows security observation triage.**

Sentinel IR Audit is a small, transparent toolkit for defenders who need to inspect Windows process, scheduled-task, and startup-entry observations without executing suspicious content or changing host security settings. It consists of a best-effort Windows PowerShell inventory collector and a portable Python JSONL rule engine. The rule engine uses only the Python standard library.

> **Important:** Findings are investigative leads, **not** proof of compromise. This is an early-stage security utility, not an antivirus, EDR, forensic acquisition product, or a substitute for authorization and human investigation.

## What it does

- Collects *read-only* host observations from local Windows APIs and registry locations; writes only to a chosen output file.
- Keeps process command lines, task arguments, and Run/RunOnce values **excluded by default** for privacy.
- Parses local JSONL observations without executing any input or contacting a server.
- Emits documented rule IDs, severity, potential MITRE ATT&CK mappings, and follow-up guidance in JSONL.
- Avoids including raw command lines in findings output.
- Provides synthetic sample observations, unit tests and CI to make behavior inspectable.

It does **not** kill processes, remove files, change policies, modify registry entries, contact network endpoints, resolve payloads, or attempt exploitation.

## Requirements

- **Analyzer:** Python 3.10+ (Windows, Linux, macOS; no runtime dependencies).
- **Optional collector:** Windows PowerShell 5.1+ on a Windows host. Some inventory sources may require elevated rights; run with the least privilege available.

## Quick start: synthetic data (safe anywhere)

From a checkout, install locally:

```bash
python -m pip install -e .
sentinel-ir-audit scan \
  --input examples/synthetic-windows-observations.jsonl \
  --output findings.jsonl \
  --summary summary.json
```

Or without installing:

```bash
PYTHONPATH=src python -m sentinel_ir_audit scan \
  --input examples/synthetic-windows-observations.jsonl \
  --output findings.jsonl \
  --summary summary.json
```

`findings.jsonl` contains one JSON object per rule match. `summary.json` summarizes counts by severity. Outputs are written **only after** input validation succeeds; the tool refuses to use the input file as an output target. Existing output report paths are **not overwritten by default**; pass `--overwrite` only after confirming the target paths.

## Collect a local Windows snapshot (optional)

On your **own or explicitly authorized** Windows host:

```powershell
.\collectors\Collect-WindowsSnapshot.ps1 -OutputPath .\snapshot.jsonl
python -m sentinel_ir_audit scan --input .\snapshot.jsonl --output .\findings.jsonl --summary .\summary.json
```

By default the collector inventories process names and paths, scheduled-task names and executables, and Run/RunOnce names and registry paths. This limits privacy exposure but also reduces detection coverage for rules that require command details. A missing indicator must **not** be interpreted as a clean host.

If analysis requires full command details, use an explicitly authorized collection, understand the privacy implications and keep the output local:

```powershell
.\collectors\Collect-WindowsSnapshot.ps1 -OutputPath .\snapshot-sensitive.jsonl -IncludeCommandDetails
```

**Do not commit, upload, or paste real host snapshots, credentials, internal asset details, customer data, or sensitive command lines into public issues.** Prefer synthetic data for bug reports.

## Input JSONL schema

Each nonblank line is a JSON object with `kind` plus fields relevant to that kind:

| `kind` | Required field | Optional fields (strings) |
| --- | --- | --- |
| `process` | `name` | `executable_path`, `command_line`, `parent_name`, `timestamp` |
| `scheduled_task` | `task_name` | `executable`, `arguments`, `task_path`, `timestamp` |
| `startup_entry` | `name` | `command`, `registry_key`, `timestamp` |

Unknown fields are discarded, optional null fields are treated as empty strings, and unexpected types are rejected. The analyzer accepts up to 50,000 records, with a 128 KiB limit per line. It never runs commands found in the input.

Example (fictional):

```json
{"kind":"scheduled_task","task_name":"DemoTempUpdater","executable":"C:\\Users\\Example\\AppData\\Local\\Temp\\demo-updater.exe"}
```

## Detection rules

| Rule | Potential indicator | Severity |
| --- | --- | --- |
| `SIA-001` | Execution reference in an OS/user temp directory | Medium for process, high for persistence |
| `SIA-002` | Encoded PowerShell invocation | Medium |
| `SIA-003` | Hidden script host in a persistence entry | Medium |
| `SIA-004` | Common Windows system process name outside expected directory | High |
| `SIA-005` | Persistence entry referencing Downloads | Medium |

See [detection rationale and limitations](docs/detections.md) and [threat model](docs/threat-model.md). All rules can produce false positives; trusted-directory checks do not validate signatures or files on disk.

## CI-oriented use

Run locally:

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

Choose `--fail-on high` (or `medium`, `low`, `critical`) to return exit code `3` when matching findings are present. Exit code `0` means the input was analyzed successfully **without crossing that threshold**, not that the host is safe. Invalid input or a file error returns `2`.

```bash
sentinel-ir-audit scan --input examples/synthetic-windows-observations.jsonl \
  --output findings.jsonl --fail-on high
```

## Privacy, scope and security

- No network traffic is initiated by the collector or analyzer.
- No suspicious payloads are executed, decoded, downloaded, or remediated.
- The collector is best effort; permission-denied data can be missing.
- The report intentionally omits raw command lines, but entity names and local file paths in snapshots may still be sensitive.
- The project has not been validated as a comprehensive threat detector or tested across all Windows versions.
- PowerShell syntax and runtime checks run in Windows CI; tests outside Windows cannot exercise the collector.

Please read [SECURITY.md](SECURITY.md) before submitting reports.

## Contributing

Small reproducible defensive rules, false-positive tests, safer privacy defaults, documentation and Windows compatibility fixes are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md). Please do not submit live malware, customer logs, credentials, exploit chains or other offensive artifacts.

## License

MIT — see [LICENSE](LICENSE).
