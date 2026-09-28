# Constitution

## Evidence Scope

The only product evidence is the closed corpus named in `specs/001-omegas-reverse/spec.md`.
External documentation may guide infrastructure and tools, but it never proves product behavior.

## Safety Boundary

This project is offline. It does not connect to an ECU, transmit to hardware, erase or write flash, bypass protections, extract credentials, or claim physical validation.

## Governance

GitHub is the durable authority. Each investigation slice uses one Issue, one WorkUnit, one branch, one draft PR, and one evidence trail unless the repository bootstrap itself is the initial authority-creating commit.

## Claim Contract

Every technical claim must be `OBSERVED`, `DERIVED`, `HYPOTHESIS`, `REFUTED`, or `UNKNOWN` and must cite file hash plus offset, log line, command, or artifact.
