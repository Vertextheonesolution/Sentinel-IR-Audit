# CVP application readiness — evidence-led checklist

_Reviewed: 2026-10-13. This is a personal planning document, not a verification by Anthropic._

## Current official guidance

- [CVP Help Center](https://support.claude.com/en/articles/14604842-cyber-verification-program): October 2026 program update; individual researchers may apply for **Defense Access only** on a paid plan, while organizations can apply for other tiers as appropriate. Submit through Anthropic's Verification Portal. Anthropic aims to send a decision or request for information within seven business days; there is no guarantee of approval.
- [Program announcement](https://www.anthropic.com/news/cyber-verification-program): Defense Access covers authorized defensive work, incident response, malware analysis, and vulnerability analysis. Organization examples include teams defending systems they own or maintain, small security firms, and open-source maintainers.
- [Security requirements](https://support.claude.com/en/articles/17202708-cyber-verification-program-security-requirements): individual Defense Access requires authentication via a supported identity provider with MFA; phishing-resistant MFA (passkey/security key/smartcard) is required by **2026-12-15**, and email magic-link sign-in is not permitted. Long-lived API keys must also cease by that date. Until then, any permitted personal CVP API key is subject to strict storage and at-least-weekly rotation requirements.
- The CVP grant does not authorize testing other people's systems, distributing a CVP session, or exposing client/company data. Anthropic also restricts using the grant for customer-facing products without separate approval.

## Grounded public evidence

| Artifact | Status | Evidentiary weight |
| --- | --- | --- |
| [Sentinel IR Audit](https://github.com/Vertextheonesolution/Sentinel-IR-Audit) | Public, maintained by repository owner | Demonstrates defensive tooling work, tests, and a public maintenance history |
| [Improvement PR #1](https://github.com/Vertextheonesolution/Sentinel-IR-Audit/pull/1) | Merged into own repository | Demonstrates self-maintenance only, **not** externally trusted maintainership |
| [Safety CLI PR #924](https://github.com/pyupio/safety/pull/924) | Open as last checked 2026-10-13 | Submitted external bug fix, not accepted/merged |
| [Yelp detect-secrets PR #1003](https://github.com/Yelp/detect-secrets/pull/1003) | Open as last checked 2026-10-13 | Submitted external defensive tooling fix, not accepted/merged |
| [CVP evidence record](cvp-evidence.md) | Public | A link index, not a credential or approval |

Do **not** claim CVE credit, accepted third-party vulnerability disclosure, paid bug bounty, verified platform reputation, or named upstream security-maintainer responsibility without third-party evidence. A merged ordinary PR is not interchangeable with an accepted vulnerability advisory or an established security-maintainer appointment.

## Two legitimate application routes

### Individual Defense Access

1. Review the **current** form in Anthropic's Verification Portal, not only a previously rejected or older version of the portal.
2. Confirm a supported paid account and identity-provider-based MFA. Adopt passkeys or a FIDO2 security key before the December cutoff.
3. Supply independently verifiable work: authorized defensive work description, linked source code, reviewed bug fixes, real accepted security disclosures, and/or verifiable maintainership as appropriate.
4. If the portal asks for a qualifying third-party event (e.g. CVE credit, accepted disclosure, standing on a bounty platform, or security maintainer of depended-on OSS), choose only one that is actually documented. Submitted PRs alone do not establish one.
5. Avoid posting confidential security logs, employer details, customer identifiers, network topology, internal vulnerabilities, secrets or private incident evidence.

**Current assessment:** Public code and two outside contributions submitted; no recognized qualifying disclosure or external maintainer status proven as of 2026-10-13.

### Organization Defense Access

1. Ask an authorized manager/employer whether they want to submit **one organization application** on behalf of their actual security operation.
2. The organization owner/admin must control the submission and designated seats. A contractor or employee should not impersonate an approver.
3. Prepare a high-level, non-confidential verification of defensive responsibilities (firewall policy change review, incident response, operational log triage, rule/change validation) **only when employer-authorized**.
4. Document the legitimate, authorized scope, security contact, identity verification, and required access controls.
5. Submit through the official verification portal. Do not represent personal side-business registration as a security organization without credible supporting operations.

**Potential advantage:** Official guidance explicitly describes organizations with defensive SOC or infrastructure responsibilities as potential Defense applicants; this route does not depend solely on a personally credited CVE.

## Practical next steps

- Watch independent maintainers' responses to [Safety #924](https://github.com/pyupio/safety/pull/924) and [detect-secrets #1003](https://github.com/Yelp/detect-secrets/pull/1003); address substantive technical reviews and run upstream-approved CI before claiming passing test results.
- Build a small number of high-quality patches instead of bulk-submitting duplicate or speculative PRs. Respect upstream contribution rules, permissions, and rate limits.
- Test Sentinel IR Audit on separately authorized disposable Windows systems using only synthetic example data in public reports, and solicit truthful third-party usability feedback.
- Prefer legitimate disclosed-and-accepted research under vendors' coordinated vulnerability disclosure programs if actual findings emerge; never manufacture advisories or publicize unpatched details without authorization.
- For organization route, seek written approval from the security team's organization owner/admin, not just use a work email without permission.

## Application packet when eligible

Include links to official eligibility evidence, a concise scope-of-work summary that does not expose confidential operations, verified security contact/authorization where relevant, security control compliance, publicly attributable GitHub history, and a clear distinction between submissions, accepted contributions, recognized disclosures and maintained deployments.

An application packet is **ready for submission**, not guaranteed approval, only when the **then-current portal's required checkboxes and requirements can be supported truthfully**.

_Review this document against primary-source requirements and live GitHub status before each application._
