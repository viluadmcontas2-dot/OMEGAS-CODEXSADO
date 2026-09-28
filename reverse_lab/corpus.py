import hashlib
import json
import time
import zipfile
from pathlib import Path, PurePosixPath


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_manifest(paths):
    files = []
    for raw_path in paths:
        path = Path(raw_path)
        stat = path.stat()
        entry = {
            "path": str(path),
            "name": path.name,
            "size": stat.st_size,
            "sha256": sha256_file(path),
        }
        if path.suffix.lower() == ".zip":
            entry["zip_inventory"] = inventory_zip(path)
        files.append(entry)
    return {
        "schema": "omegas-reverse-corpus-manifest-v1",
        "generated_at": int(time.time()),
        "files": files,
    }


def inventory_zip(path, max_expanded_bytes=512 * 1024 * 1024):
    members = []
    total = 0
    safe = True
    blocked_reason = None

    with zipfile.ZipFile(path) as archive:
        for info in archive.infolist():
            member_name = info.filename.replace("\\", "/")
            normalized = PurePosixPath(member_name)
            reason = None
            if info.is_dir():
                kind = "directory"
            else:
                kind = "file"
            if normalized.is_absolute() or ".." in normalized.parts:
                reason = "path_traversal"
                safe = False
            total += info.file_size
            members.append(
                {
                    "name": member_name,
                    "kind": kind,
                    "compressed_size": info.compress_size,
                    "size": info.file_size,
                    "crc32": format(info.CRC, "08x"),
                    **({"blocked_reason": reason} if reason else {}),
                }
            )

    if total > max_expanded_bytes:
        safe = False
        blocked_reason = "expanded_size_limit"

    result = {
        "path": str(path),
        "safe": safe,
        "expanded_size": total,
        "max_expanded_bytes": max_expanded_bytes,
        "members": members,
    }
    if blocked_reason:
        result["blocked_reason"] = blocked_reason
    return result


def write_manifest(paths, output_path):
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    manifest = build_manifest(paths)
    output.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    return manifest
