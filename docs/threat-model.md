# Threat model and trust boundaries

## Assets

The toolkit handles process paths, task definitions, and optional command lines/autorun values from local Windows inventory. With extended collection enabled, these can include sensitive information.

## Trust boundaries

- The JSONL input is untrusted. It is parsed as data, never executed as code. Unknown fields are discarded and per-line size and record-count limits apply.
- A Windows collector reads local operating-system APIs and registry entries. It performs no elevation, network operations, remote inspection, remediation, or execution of observed commands.
- Output reports are stored locally. They may contain task or process names and must be protected as environment metadata.
- CI fixtures are deliberately fictional and cannot establish effectiveness against real threats.

## In scope

Static interpretation of supplied process, scheduled-task and Run/RunOnce startup observations. Local best-effort collection. Documented behavior tested with synthetic fixtures. Per-rule investigation recommendations.

## Out of scope

Real-time behavioral monitoring, malware removal, forensic disk imaging, event-log tampering analysis, memory analysis, exploit or vulnerability validation, credential collection, stealth, lateral movement, remote scanning, and organizational compliance certification.

## Key mitigations and unresolved risks

- Collector excludes potentially secret-bearing fields unless -IncludeCommandDetails is explicit.
- The Python analyzer never executes shell commands and has zero network dependencies.
- Findings omit full command lines; input snapshots can still contain secrets.
- Existing output files are preserved unless the user explicitly passes --overwrite; input/output aliasing is rejected.
- Input size is bounded by per-line and record caps, but the analyzer stores findings in memory; massive datasets require splitting.
- Windows compatibility requires Windows CI/runtime testing; Linux Python unit tests cannot validate PowerShell behavior.
- Static process-path checks can miss redirected paths or produce false positives.
