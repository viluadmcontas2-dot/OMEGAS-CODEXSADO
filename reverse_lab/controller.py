import argparse
import json
import os
import platform
import subprocess
import sys
import time
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
    parser.add_argument("--max-units", type=int, default=1)
    parser.add_argument("--auto-dispatch", action="store_true")
    args = parser.parse_args(argv)

    executed = []
    for _ in range(args.max_units):
        claim = claim_next_workunit(args.state_path, args.owner, args.lease_seconds)
        if not claim:
            break
        status, result = execute_workunit(claim, args.corpus_root, args.artifacts_root)
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
