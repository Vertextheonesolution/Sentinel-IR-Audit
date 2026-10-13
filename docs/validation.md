# Validation and evidence protocol

## CI checks

The GitHub Actions workflow runs Python 3.10/3.12 tests on Linux and Windows, checks PowerShell syntax, and performs a Windows-hosted collection-to-analyzer smoke test using a privacy-default snapshot.

A successful CI run validates only the GitHub-hosted environments actually exercised. It does not imply production readiness, broad Windows compatibility, real-world detection accuracy, or enterprise deployment.

Check [GitHub Actions](../actions/workflows/tests.yml) for exact commit, run, job and step statuses. Do not claim Windows runtime validation until the smoke-test job reports success.

## Controlled manual Windows validation

1. Use your own Windows 10/11 or Windows Server test machine with Python 3.10+ and PowerShell 5.1, preferably a disposable VM.
2. Review collector source and obtain appropriate system-owner authorization.
3. Run `powershell -NoProfile -File .\collectors\Collect-WindowsSnapshot.ps1 -OutputPath .\snapshot.jsonl`.
4. Confirm nonempty observations, absence of command-line details, no unexpected network activity and no host configuration changes.
5. Run `python -m sentinel_ir_audit scan --input .\snapshot.jsonl --output .\findings.jsonl --summary .\summary.json` after setting PYTHONPATH to src or installing the package.
6. Confirm the report can be parsed, review potential false positives manually and protect or delete sensitive local metadata as appropriate.
7. Repeat with a different output path; automatic snapshot overwrites are intentionally disallowed.

Do not publish real host snapshots or company/customer logs.

## Community bug-reports

Submit only fictional JSONL observations, expected versus actual behavior, OS/PowerShell versions and sanitized error messages. No real IPs, endpoints, client names, tokens, configuration dumps, malware samples, or exploit payloads.

## CVP evidence integrity

The public code, authored rule documentation, commit history, and verified CI results can demonstrate work on defensive tooling. A newly created repository does not by itself prove public dependency, accepted vulnerability disclosure, CVE credit, bounty standing, production deployment, or organizational authorization. Do not assert any of these without independent evidence.
