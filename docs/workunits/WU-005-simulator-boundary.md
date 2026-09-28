# WU-005 — Offline simulator closure

The closed corpus supports a deterministic replay simulator specification. It does not prove ECU-side semantics or physical behavior. The simulator therefore emits observed frames and confidence-labelled hypotheses, keeps `automaticWrite == false`, and requires human review for any future action. The protocol is saturated for this corpus when WU-001 through WU-005 are `done`; new evidence reopens the queue by creating a new WorkUnit with explicit dependencies.
