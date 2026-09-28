# Specification: OMEGAS Reverse Interoperability

## Goal

Produce the most complete offline, reproducible, evidence-bound specification possible for the communication protocol and autocalibration process represented by the supplied Landi Renzo Omegas artifacts.

## Closed Corpus

- `Resources.dll`
- `ProgBase.exe`
- `EVO_L_#00567.ple`
- `EVO_#01160.ple`
- `PortmonLOGNOVO (1).zip`

ZIP members enter the corpus only after safe inventory and hash capture.

## Required Outputs

- Evidence manifest and provenance.
- WorkUnit/checkpoint registry.
- Message and field catalog.
- Sequence and state diagrams.
- Firmware and PLE structure report.
- Autocalibration state machine and responsibility map.
- Mobile-app architecture specification with `automaticWrite == false`.
- Offline parsers, fixtures, replay tests, and coverage report.

## Non Goals

- No ECU or vehicle operations.
- No flash erase/write or bootloader action.
- No bypass of licensing, authentication, or protections.
- No publication of proprietary binaries by default.
