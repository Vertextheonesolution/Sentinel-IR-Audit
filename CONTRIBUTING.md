# Contributing

Contributions are welcome for defensive triage, reproducibility and reliability.

1. Open an issue describing an observable false positive or a privacy-safe detection idea. Share **synthetic** input; do not share production logs or customer infrastructure.
2. Add a unit test that demonstrates the current and desired results. Favor narrow signatures over broad false-positive-prone conditions.
3. Keep runtime dependencies minimal, and do not add automatic remediation, remote telemetry, active probing or payload execution.
4. Run `PYTHONPATH=src python -m unittest discover -s tests -v` before proposing changes.
5. Document uncertainty, legitimate alternatives, and the reason for severity changes.

The maintainer may decline features that expand offensive behavior, add network collection, or create data-leakage risks. All contributors must have rights to the material they submit.
