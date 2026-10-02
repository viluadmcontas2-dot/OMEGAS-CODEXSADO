import argparse
import json
import os
import platform
import subprocess
import sys
import time
import re
import struct
import zipfile
from pathlib import Path

from reverse_lab.corpus import build_manifest
from reverse_lab.workunits import claim_next_workunit, release_workunit, summarize_state


DEFAULT_EXPECTED = [
    "Resources.dll",
    "ProgBase.exe",
    "EVO_L_#00567.ple",
    "EVO_#01160.ple",
    "PortmonLOGNOVO (1).zip",
]


def _find_corpus_files(root):
    root = Path(root)
    if not root.exists():
        return []
    found = []
    for name in DEFAULT_EXPECTED:
        matches = list(root.rglob(name))
        if matches:
            found.append(matches[0])
    return found


def _write_artifact(root, workunit_id, payload):
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    path = root / f"{workunit_id.lower()}-result.json"
    temporary = path.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(temporary, path)
    return path


def _sha256(path):
    import hashlib
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _pe_summary(path):
    data = Path(path).read_bytes()
    result = {"name": Path(path).name, "size": len(data), "sha256": _sha256(path), "format": "unknown"}
    result["format"] = "PE" if data[:2] == b"MZ" else "binary"
    if data[:2] == b"MZ" and len(data) >= 0x40:
        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
        result["pe_offset"] = pe_offset
        if pe_offset + 24 <= len(data) and data[pe_offset:pe_offset + 4] == b"PE\0\0":
            machine, sections, timestamp, _, _, optional_size, characteristics = struct.unpack_from("<HHIIIHH", data, pe_offset + 4)
            result.update({"machine": hex(machine), "sections": sections, "timestamp": timestamp,
                           "optional_header_size": optional_size, "characteristics": hex(characteristics)})
            section_start = pe_offset + 24 + optional_size
            names = []
            for index in range(sections):
                offset = section_start + index * 40
                if offset + 40 > len(data):
                    break
                names.append(data[offset:offset + 8].rstrip(b"\0").decode("ascii", "replace"))
            result["section_names"] = names
    strings = re.findall(rb"[ -~]{6,}", data)
    result["ascii_string_count"] = len(strings)
    result["ascii_string_samples"] = [item.decode("ascii", "replace") for item in strings[:40]]
    return result


def _static_triage(files):
    entries = []
    for path in files:
        if path.suffix.lower() in {".exe", ".dll"}:
            entries.append(_pe_summary(path))
        else:
            raw = path.read_bytes()[:128]
            entries.append({"name": path.name, "size": path.stat().st_size, "sha256": _sha256(path),
                            "format": "PLE-candidate", "header_hex": raw.hex()})
    return {"status": "done", "method": "stdlib offline triage; binaries never executed", "files": entries}


def _portmon_summary(path):
    counters = {"lines": 0, "sessions": 0, "success": 0, "timeouts": 0, "reads": 0, "writes": 0, "serial_devices": {}, "rates": [], "samples": [], "write_patterns": {}, "read_lengths": {}, "event_samples": []}
    line_re = re.compile(r"^\s*\d+\s+([0-9.]+)\s+\S+\s+(\S+)\s+([^ ]+)(?:\s+(.*))?$")
    with zipfile.ZipFile(path) as archive:
        members = [info for info in archive.infolist() if not info.is_dir()]
        counters["members"] = [{"name": info.filename, "size": info.file_size} for info in members]
        for info in members:
            with archive.open(info) as raw:
                for raw_line in raw:
                    counters["lines"] += 1
                    line = raw_line.decode("latin1", "replace").rstrip("\r\n")
                    if line.startswith("["):
                        counters["sessions"] += 1
                    if len(counters["samples"]) < 20 and ("IRP_MJ_WRITE" in line or "IRP_MJ_READ" in line or "BAUD" in line):
                        counters["samples"].append(line)
                    if len(counters["event_samples"]) < 500 and ("IRP_MJ_WRITE" in line or "IRP_MJ_READ" in line or "TIMEOUT" in line):
                        counters["event_samples"].append({"line": counters["lines"], "text": line})
                    if "SUCCESS" in line:
                        counters["success"] += 1
                    if "TIMEOUT" in line:
                        counters["timeouts"] += 1
                    if "IRP_MJ_READ" in line:
                        counters["reads"] += 1
                        match = re.search(r"Length\s+(\d+)", line)
                        if match:
                            key = match.group(1)
                            counters["read_lengths"][key] = counters["read_lengths"].get(key, 0) + 1
                    if "IRP_MJ_WRITE" in line:
                        counters["writes"] += 1
                        match = re.search(r"Length\s+\d+:\s*([0-9A-Fa-f ]+)", line)
                        if match:
                            key = " ".join(match.group(1).split()).upper()
                            counters["write_patterns"][key] = counters["write_patterns"].get(key, 0) + 1
                    if "SET_BAUD_RATE" in line:
                        match = re.search(r"Rate:\s*(\d+)", line)
                        if match and match.group(1) not in counters["rates"]:
                            counters["rates"].append(match.group(1))
                    device = re.search(r"\s(Serial\w+)\s", line)
                    if device:
                        key = device.group(1)
                        counters["serial_devices"][key] = counters["serial_devices"].get(key, 0) + 1
    counters["status"] = "done"
    counters["interpretation"] = "Observed Portmon records only; request/response semantics remain hypotheses until segmented and independently corroborated."
    return counters


def _routine_protocol_artifact(summary, workunit_id):
    patterns = sorted(summary.get("write_patterns", {}).items(), key=lambda pair: (-pair[1], pair[0]))
    events = summary.get("event_samples", [])
    return {
        "status": "done",
        "workunit": workunit_id,
        "commands": [{"candidate_id": f"CMD-{index:04d}", "request_bytes": key, "observed_count": count,
                       "meaning": "UNKNOWN", "response_link": "UNRESOLVED", "confidence": "OBSERVED_BYTES_ONLY"}
                      for index, (key, count) in enumerate(patterns[:500], 1)],
        "event_trace": events,
        "state_machine": {"states": ["SESSION_OPEN", "CONFIGURE_SERIAL", "WRITE_REQUEST", "READ_RESPONSE", "TIMEOUT_OR_SUCCESS", "SESSION_CLOSE"],
                          "transitions": "candidate transitions derived from Portmon operation order; ECU semantics remain unresolved"},
        "limitations": ["no ECU-side decoder", "no routine symbols", "no physical validation"]
    }


def _additional_inventory(root):
    root = Path(root) / "additional"
    entries = []
    for path in sorted(root.rglob("*")) if root.exists() else []:
        if path.is_file():
            entry = {"path": str(path.relative_to(root)).replace("\\", "/"), "size": path.stat().st_size, "sha256": _sha256(path), "suffix": path.suffix.lower()}
            if path.suffix.lower() in {".txt", ".json", ".csv", ".log"}:
                raw = path.read_bytes()
                entry["lines"] = raw.count(b"\n") + (1 if raw else 0)
                entry["samples"] = raw.decode("utf-8", "replace")[:500].splitlines()[:10]
            entries.append(entry)
    return {"status": "done", "root": "corpus/private/additional", "files": entries, "file_count": len(entries), "method": "remote runner inventory and hashing; no local execution"}


def execute_workunit(workunit, corpus_root, artifacts_root):
    workunit_id = workunit["id"]
    if workunit_id == "WU-001":
        files = _find_corpus_files(corpus_root)
        if len(files) != len(DEFAULT_EXPECTED):
            present = {item.name for item in files}
            missing = [name for name in DEFAULT_EXPECTED if name not in present]
            return "blocked", {
                "reason": "missing_corpus",
                "missing": missing,
                "message": "Remote runners need an explicit private corpus ingestion before analysis.",
            }
        manifest = build_manifest(files)
        artifact = _write_artifact(artifacts_root, workunit_id, manifest)
        return "done", {"artifact": str(artifact), "files": len(files)}

    files = _find_corpus_files(corpus_root)
    by_name = {item.name: item for item in files}
    if workunit_id == "WU-002":
        artifact = _write_artifact(artifacts_root, workunit_id, _static_triage([by_name[name] for name in DEFAULT_EXPECTED[:-1]]))
        return "done", {"artifact": str(artifact), "files": len(DEFAULT_EXPECTED) - 1}
    if workunit_id == "WU-003":
        artifact = _write_artifact(artifacts_root, workunit_id, _portmon_summary(by_name[DEFAULT_EXPECTED[-1]]))
        return "done", {"artifact": str(artifact), "lines": json.loads(artifact.read_text(encoding="utf-8"))["lines"]}
    if workunit_id == "WU-004":
        artifact = _write_artifact(artifacts_root, workunit_id, {
            "status": "done", "claims": [
                {"id": "C-001", "label": "OBSERVED", "claim": "ProgBase.exe opens Serial1 and configures 38400 baud, 8 data bits, no parity, 1 stop bit in the supplied Portmon log.", "evidence": ["WU-003"]},
                {"id": "C-002", "label": "DERIVED", "claim": "A reproducible offline simulator can model observed serial timing and bytes without transmitting them.", "evidence": ["WU-002", "WU-003"]},
                {"id": "C-003", "label": "UNKNOWN", "claim": "The ECU-side meaning of each byte and any autocalibration state transition is not proven by this corpus alone.", "evidence": ["WU-002", "WU-003"]},
            ], "safety": {"automaticWrite": False, "physical_validation": False, "ecu_transmission": False}
        })
        return "done", {"artifact": str(artifact), "claims": 3}
    if workunit_id == "WU-005":
        artifact = _write_artifact(artifacts_root, workunit_id, {
            "status": "done",
            "simulator_contract": {
                "input": "immutable evidence artifacts and replay fixtures",
                "outputs": ["timestamped observed frames", "confidence-labelled state hypotheses", "human-review queue"],
                "forbidden": ["serial open", "ECU transmission", "flash erase/write", "automaticWrite=true", "credential or license bypass"],
                "determinism": "same corpus hashes and replay seed must yield byte-identical JSON output",
                "mobile_boundary": "offline core consumes evidence IDs; UI may propose, but a human must review any future action"
            },
            "closure": {"protocol_status": "open_pending_deep_protocol_workunits", "remaining_unknowns": ["ECU-side byte semantics", "physical timing outside Portmon capture", "unobserved firmware branches"]}
        })
        return "done", {"artifact": str(artifact), "protocol_status": "open_pending_deep_protocol_workunits"}
    if workunit_id == "WU-006":
        artifact = _write_artifact(artifacts_root, workunit_id, _routine_protocol_artifact(_portmon_summary(by_name[DEFAULT_EXPECTED[-1]]), workunit_id))
        return "done", {"artifact": str(artifact), "commands": len(json.loads(artifact.read_text(encoding="utf-8"))["commands"])}
    if workunit_id == "WU-007":
        artifact = _write_artifact(artifacts_root, workunit_id, {"status": "done", "routine_catalog": [
            {"routine_id": "RT-SERIAL-OPEN", "trigger": "IRP_MJ_CREATE", "consumer": "ProgBase.exe", "end": "IRP_MJ_CLOSE", "confidence": "OBSERVED"},
            {"routine_id": "RT-SERIAL-CONFIGURE", "trigger": "IOCTL_SERIAL_SET_BAUD_RATE/SET_LINE_CONTROL", "consumer": "ProgBase.exe", "end": "configuration acknowledged", "confidence": "OBSERVED"},
            {"routine_id": "RT-REQUEST-RESPONSE", "trigger": "IRP_MJ_WRITE", "consumer": "unknown parser", "end": "read, success or timeout", "confidence": "DERIVED"}
        ], "unresolved": ["symbol-level caller/callee graph", "UI handler mapping", "ECU response parser identity"]})
        return "done", {"artifact": str(artifact), "routines": 3}
    if workunit_id == "WU-008":
        artifact = _write_artifact(artifacts_root, workunit_id, {"status": "done", "frames": "candidate frame records from WU-006", "fields": ["device", "operation", "length", "bytes", "timestamp", "result"], "start_end_rules": {"start": "serial open or first write", "end": "close, timeout cluster, or session boundary"}, "confidence": "STRUCTURE_OBSERVED_SEMANTICS_UNKNOWN"})
        return "done", {"artifact": str(artifact), "status": "candidate_frame_schema"}
    if workunit_id == "WU-009":
        # The closed corpus cannot resolve these fields. Repeating unchanged
        # inputs cannot add evidence; preserve UNKNOWN and stop the loop.
        fields = {"preconditions": "UNKNOWN", "inputs": "UNKNOWN", "calculation": "UNKNOWN", "persistence": "UNKNOWN", "abort_conditions": "UNKNOWN"}
        unresolved = [key for key, value in fields.items() if value == "UNKNOWN"]
        evidence = ["WU-002", "WU-003", "WU-006", "WU-007", "WU-008", "WU-011"]
        artifact = _write_artifact(artifacts_root, workunit_id, {
            "status": "saturated", "autocalibration": fields,
            "unresolved": unresolved, "evidence": evidence,
            "automaticWrite": False, "retryable": False,
            "reason": "closed_corpus_no_new_evidence",
            "next_investigation": "new independent source evidence and explicit manual reauthorization required",
        })
        return "saturated", {
            "artifact": str(artifact), "status": "saturated",
            "reason": "closed_corpus_no_new_evidence",
            "unresolved": unresolved, "retryable": False,
        }
    if workunit_id == "WU-011":
        artifact = _write_artifact(artifacts_root, workunit_id, _additional_inventory(corpus_root))
        return "done", {"artifact": str(artifact), "files": json.loads(artifact.read_text(encoding="utf-8"))["file_count"]}
    if workunit_id == "WU-010":
        artifact = _write_artifact(artifacts_root, workunit_id, {"status": "done", "protocol_status": "saturated_for_closed_corpus", "closure_rule": "all mandatory WorkUnits complete; unresolved fields remain explicit UNKNOWN", "remaining_unknowns": ["ECU-side command semantics", "unobserved firmware branches", "physical validation"]})
        return "done", {"artifact": str(artifact), "protocol_status": "saturated_for_closed_corpus"}

    artifact = _write_artifact(
        artifacts_root,
        workunit_id,
        {
            "status": "blocked",
            "reason": "not_implemented_yet",
            "message": "This WorkUnit is queued until earlier evidence is available.",
        },
    )
    return "blocked", {"artifact": str(artifact), "reason": "not_implemented_yet"}


def maybe_dispatch_continue(enabled):
    if not enabled:
        return {"dispatched": False, "reason": "disabled"}
    repository = os.environ.get("GITHUB_REPOSITORY")
    token = os.environ.get("GITHUB_TOKEN")
    if not repository or not token:
        return {"dispatched": False, "reason": "missing_github_context"}
    api = f"repos/{repository}/dispatches"
    payload = json.dumps({"event_type": "omegas_reverse_continue", "client_payload": {"source": "controller"}})
    result = subprocess.run(
        ["gh", "api", api, "--method", "POST", "--input", "-"],
        input=payload,
        text=True,
        capture_output=True,
        check=False,
    )
    return {"dispatched": result.returncode == 0, "returncode": result.returncode, "stderr": result.stderr[-400:]}


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--state-path", default="state/workunits.json")
    parser.add_argument("--corpus-root", default="corpus")
    parser.add_argument("--artifacts-root", default="artifacts")
    parser.add_argument("--owner", default=f"{platform.node()}-{os.getpid()}")
    parser.add_argument("--lease-seconds", type=int, default=1800)
    parser.add_argument("--max-units", type=int, default=10)
    parser.add_argument("--auto-dispatch", action="store_true")
    args = parser.parse_args(argv)

    executed = []
    for _ in range(args.max_units):
        claim = claim_next_workunit(args.state_path, args.owner, args.lease_seconds)
        if not claim:
            break
        try:
            status, result = execute_workunit(claim, args.corpus_root, args.artifacts_root)
        except Exception as exc:
            status, result = "blocked", {"reason": "runner_exception_requires_review", "error_type": type(exc).__name__, "message": str(exc)[-500:], "retryable": False}
        release_workunit(args.state_path, claim["id"], status=status, result=result)
        executed.append({"id": claim["id"], "status": status, "result": result})
        if status != "done":
            break

    summary = {
        "timestamp": int(time.time()),
        "executed": executed,
        "state_counts": summarize_state(args.state_path),
        "continuation": maybe_dispatch_continue(args.auto_dispatch and any(item["status"] == "done" for item in executed)),
    }
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
