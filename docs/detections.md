# Detection rationale

Sentinel IR Audit provides deterministic triage observations, **not** threat attribution or proof of compromise. Each rule operates only on JSONL fields, not live filesystem state. MITRE ATT&CK technique IDs are context pointers, not confirmations that a technique was used.

| Rule | Logic | Common legitimate explanation | Suggested manual triage |
| --- | --- | --- | --- |
| SIA-001 | Process image or persistence entry references a recognized Windows Temp, user AppData Local Temp, or TEMP environment-variable path. | A temporary software installation or enterprise deployment agent. | Inspect file signer/hash and deployment change records; verify if persistence is approved. |
| SIA-002 | Recognizes -enc / -EncodedCommand in a PowerShell command context. | Legitimate encoded administrative automation. | Review script source and execution authorization without executing unknown input. |
| SIA-003 | PowerShell or another common script host with -WindowStyle Hidden in a scheduled task or Run/RunOnce entry. | Approved unattended maintenance or automation. | Validate origin, task author, access-control context and intended function. |
| SIA-004 | svchost.exe, lsass.exe, services.exe or winlogon.exe observed outside typical Windows System32/SysWOW64 directories. | Incomplete path data, nonstandard Windows deployment or renamed troubleshooting copy. | Investigate path and signature, confirm host identity and collect additional evidence. |
| SIA-005 | Startup entry or task references a file in a user's Downloads directory. | A legitimate but poorly packaged startup tool. | Validate authorization and move approved software to a managed install location. |

## Visibility limits

The default collector omits command-line details, so rules SIA-002, SIA-003, and portions of SIA-001 and SIA-005 may be ineffective. This is intentional: privacy is the default. No analyzer finding implies no match was observed in the fields supplied; it does **not** imply a clean host.

Path matching is string-based and does not resolve environment variables, junctions, symlinks, filesystem redirection or digital signatures. -IncludeCommandDetails may expose secrets. Investigations must be scoped and authorized.

## Output interpretation

Findings have record_index referring to a physical line number of the local input file, plus the rule ID, severity, matched field names, stable rationale, and analyst recommendation. They intentionally do not include raw command-line text. Multiple rules may match one observation. Severity reflects triage priority, not verified harm.
