# Security policy

## Intended defensive use

This project is for authorized host observation collection and **offline** triage. It does not authorize scanning, access to, or testing of systems belonging to others. No detection is a definitive compromise determination.

## Reporting a vulnerability

If GitHub private vulnerability reporting is enabled, use the repository's **Security → Report a vulnerability** flow. Otherwise, open a minimal issue asking the maintainer for a private reporting channel **without** posting exploit details, credentials, real customer data, private infrastructure identifiers or raw security logs.

Please describe affected versions, minimal synthetic reproduction, impact and any available defensive mitigation. We do not currently promise a fixed response time or coordinated disclosure deadline.

## Sensitive data

The default Windows collector omits process command lines, scheduled-task arguments, and startup registry values. With `-IncludeCommandDetails`, those fields may contain access tokens, passwords, hostnames, user names and paths. Treat snapshots as sensitive; keep them local, apply organizational handling policies, and use only synthetic records in issues and pull requests.

The analyzer outputs entity names and rule metadata, not raw command lines; names may nonetheless identify local systems or tasks. Review outputs before distributing them.

## Known limitations

- The tool does not validate file signatures, process provenance, remote indicators or event integrity.
- A successful run is not an all-clear, especially when details are omitted or inventory access is limited.
- The collector only writes observations and does not perform forensic acquisition, EDR response or tamper-proof logging.
- Do not use this software as the sole basis for destructive action or compliance claims.
