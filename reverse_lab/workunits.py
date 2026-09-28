import json
import os
import time
from pathlib import Path


TERMINAL_STATUSES = {"done", "blocked", "failed", "saturated"}


def read_state(path):
    path = Path(path)
    return json.loads(path.read_text(encoding="utf-8"))


def write_state(path, state):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(state, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(temporary, path)


def _completed_ids(workunits):
    return {item["id"] for item in workunits if item.get("status") == "done"}


def _is_ready(item, completed, now):
    if item.get("status") == "ready":
        return all(dep in completed for dep in item.get("depends_on", []))
    if item.get("status") == "running" and item.get("lease_expires_at", 0) <= now:
        return all(dep in completed for dep in item.get("depends_on", []))
    return False


def claim_next_workunit(path, owner, lease_seconds):
    state = read_state(path)
    now = int(time.time())
    completed = _completed_ids(state.get("workunits", []))

    for item in state.get("workunits", []):
        if _is_ready(item, completed, now):
            item["status"] = "running"
            item["owner"] = owner
            item["lease_expires_at"] = now + lease_seconds
            item["claimed_at"] = now
            item.setdefault("attempts", 0)
            item["attempts"] += 1
            write_state(path, state)
            return dict(item)
    return None


def release_workunit(path, workunit_id, status, result=None):
    if status not in TERMINAL_STATUSES and status != "ready":
        raise ValueError(f"unsupported status: {status}")
    state = read_state(path)
    now = int(time.time())
    for item in state.get("workunits", []):
        if item["id"] == workunit_id:
            item["status"] = status
            item["updated_at"] = now
            item.pop("owner", None)
            item.pop("lease_expires_at", None)
            if result is not None:
                item["result"] = result
            write_state(path, state)
            return dict(item)
    raise KeyError(workunit_id)


def summarize_state(path):
    state = read_state(path)
    counts = {}
    for item in state.get("workunits", []):
        counts[item.get("status", "unknown")] = counts.get(item.get("status", "unknown"), 0) + 1
    return counts
