# OMEGAS-REVERSE

Offline, evidence-bound interoperability investigation for Landi Renzo Omegas artifacts.

The repository is private and contains the authorized investigation corpus plus its local manifest. The runners operate from a durable WorkUnit state file and stop with explicit blockers when the corpus is absent or when a question is saturated.

## Rules

- GitHub is the authority for issues, workunits, branches, pull requests, and runner evidence.
- The product evidence corpus is closed to the five supplied files and safe ZIP members after inventory.
- No ECU connection, physical transmission, bootloader entry, flash erase/write, credential extraction, license bypass, or protection bypass.
- `automaticWrite == false` for any future mobile-app-facing specification.
- Claims must be labeled `OBSERVED`, `DERIVED`, `HYPOTHESIS`, `REFUTED`, or `UNKNOWN`.

## Local Corpus Bootstrap

Run this only on a machine that has the authorized files:

```powershell
.\scripts\bootstrap_local_corpus.ps1
python -m reverse_lab.controller --state-path state/workunits.json --corpus-root corpus/private --artifacts-root artifacts
```

Remote GitHub-hosted runners do not see local Windows paths. They require an explicit private ingestion path before they can analyze the corpus.
