# WU-001 — Corpus identity and provenance

Status: ready

Scope: hash and inventory the five authorized artifacts, record safe ZIP members, and publish only reproducible metadata alongside the supplied corpus.

Acceptance evidence:

- all five files are present under `corpus/private/`;
- SHA-256 and byte sizes are recorded in `artifacts/local-corpus-manifest.json`;
- ZIP path traversal and expanded-size checks are enforced;
- no ECU, transport, bootloader, flash, credential, or protection-bypass action is permitted.

The next WorkUnits may consume this identity record, but every observation must retain its source hash and confidence label.
