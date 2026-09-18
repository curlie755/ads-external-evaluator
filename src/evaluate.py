#!/usr/bin/env python3
"""Immutable, source-only material collector for the Harness bootstrap boundary.

This process accepts no candidate checkout, model credential, or publisher
credential. It reads bounded Git object data and returns it to trusted Harness
main source, which alone invokes Claude and publishes a status.
"""
from __future__ import annotations

import argparse
import base64
import difflib
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

TARGET_REPOSITORY = "curlie755/agentic-development-harness"
MAX_FILES = 50
MAX_FILE_BYTES = 32 * 1024
MAX_TOTAL_BYTES = 88 * 1024
MAX_REVIEW_REQUEST_BYTES = 192 * 1024
SHA = re.compile(r"^[0-9a-f]{40}$")
SAFE_PATH = re.compile(r"^[^\x00\r\n]+$")


class Refusal(RuntimeError):
    """A fail-closed evaluator boundary breach."""


def compact(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def reject_duplicate(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise Refusal("duplicate JSON member")
        result[key] = value
    return result


def strict_json(raw: str | bytes, label: str) -> Any:
    try:
        return json.loads(raw, object_pairs_hook=reject_duplicate)
    except (TypeError, json.JSONDecodeError, Refusal) as error:
        raise Refusal(f"{label} is not strict JSON") from error


def sha(value: Any) -> str:
    if not isinstance(value, str) or not SHA.fullmatch(value.lower()):
        raise Refusal("invalid commit identity")
    return value.lower()


def source_path(value: Any) -> str:
    if not isinstance(value, str) or not SAFE_PATH.fullmatch(value) or value.startswith("/") or ".." in value.split("/"):
        raise Refusal("unsafe source path")
    return value


def api_request(method: str, api: str, endpoint: str, token: str, payload: dict[str, Any] | None = None) -> Any:
    body = None if payload is None else compact(payload).encode("utf-8")
    request = urllib.request.Request(f"{api.rstrip('/')}{endpoint}", data=body, method=method)
    request.add_header("Accept", "application/vnd.github+json")
    request.add_header("X-GitHub-Api-Version", "2022-11-28")
    request.add_header("Authorization", f"Bearer {token}")
    if body is not None:
        request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return strict_json(response.read().decode("utf-8"), "GitHub REST response")
    except (urllib.error.URLError, urllib.error.HTTPError, UnicodeDecodeError, Refusal) as error:
        raise Refusal(f"GitHub REST request failed: {error.__class__.__name__}") from error


def get(api: str, token: str, endpoint: str) -> Any:
    return api_request("GET", api, endpoint, token)


def event_identity(event: dict[str, Any], requested_number: str = "") -> tuple[int, str | None, str | None]:
    repository, pull = event.get("repository"), event.get("pull_request")
    if not isinstance(repository, dict) or repository.get("full_name") != TARGET_REPOSITORY:
        raise Refusal("only the configured Harness repository is eligible")
    number = event.get("number") if isinstance(pull, dict) else requested_number
    if isinstance(number, str) and re.fullmatch(r"[1-9][0-9]*", number):
        number = int(number)
    if type(number) is not int or number < 1:
        raise Refusal("invalid pull request number")
    if not isinstance(pull, dict):
        return number, None, None
    if not isinstance(pull.get("head"), dict) or not isinstance(pull.get("base"), dict) or pull["base"].get("ref") != "main":
        raise Refusal("only Harness pull requests targeting main are eligible")
    head = sha(pull["head"].get("sha"))
    base = sha(pull["base"].get("sha"))
    return number, head, base


def identity(api: str, token: str, number: int) -> dict[str, Any]:
    pull = get(api, token, f"/repos/{TARGET_REPOSITORY}/pulls/{number}")
    if not isinstance(pull, dict) or not isinstance(pull.get("head"), dict) or not isinstance(pull.get("base"), dict) or pull["base"].get("ref") != "main":
        raise Refusal("pull request readback is malformed or targets another base")
    head = sha(pull["head"].get("sha"))
    base = sha(pull["base"].get("sha"))
    changed_files = pull.get("changed_files")
    if type(changed_files) is not int or not 0 < changed_files <= MAX_FILES:
        raise Refusal("changed file count is outside safe bounds")
    commit = get(api, token, f"/repos/{TARGET_REPOSITORY}/git/commits/{head}")
    tree = sha(commit.get("tree", {}).get("sha") if isinstance(commit, dict) and isinstance(commit.get("tree"), dict) else None)
    comparison = get(api, token, f"/repos/{TARGET_REPOSITORY}/compare/{base}...{head}")
    if not isinstance(comparison, dict) or comparison.get("merge_base_commit", {}).get("sha") != base:
        raise Refusal("pull request must contain its current base")
    return {"repository": TARGET_REPOSITORY, "number": number, "head": head, "base": base, "tree": tree, "changed_files": changed_files}


def tree(api: str, token: str, commit: str) -> dict[str, dict[str, str]]:
    commit_data = get(api, token, f"/repos/{TARGET_REPOSITORY}/git/commits/{commit}")
    tree_sha = sha(commit_data.get("tree", {}).get("sha") if isinstance(commit_data, dict) and isinstance(commit_data.get("tree"), dict) else None)
    tree_data = get(api, token, f"/repos/{TARGET_REPOSITORY}/git/trees/{tree_sha}?recursive=1")
    entries = tree_data.get("tree") if isinstance(tree_data, dict) else None
    if not isinstance(entries, list) or tree_data.get("truncated") is True:
        raise Refusal("Git tree is unavailable or truncated")
    result: dict[str, dict[str, str]] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        file_path = source_path(entry.get("path"))
        entry_sha, kind, mode = entry.get("sha"), entry.get("type"), entry.get("mode")
        if not isinstance(entry_sha, str) or not isinstance(kind, str) or not isinstance(mode, str):
            raise Refusal("malformed Git tree entry")
        result[file_path] = {"sha": sha(entry_sha), "type": kind, "mode": mode}
    return result


def blob(api: str, token: str, blob_sha: str) -> str:
    data = get(api, token, f"/repos/{TARGET_REPOSITORY}/git/blobs/{sha(blob_sha)}")
    if not isinstance(data, dict) or data.get("encoding") != "base64" or not isinstance(data.get("content"), str):
        raise Refusal("source blob is unavailable")
    try:
        raw = base64.b64decode(re.sub(r"[ \t\r\n]", "", data["content"]), validate=True)
        decoded = raw.decode("utf-8")
    except (ValueError, UnicodeDecodeError) as error:
        raise Refusal("binary or invalid UTF-8 source is out of bounds") from error
    actual = hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()
    if data.get("sha") != blob_sha or actual != blob_sha or data.get("size") != len(raw) or len(raw) > MAX_FILE_BYTES or "\0" in decoded:
        raise Refusal("source blob exceeds safe bounds")
    return decoded


def material(api: str, token: str, current: dict[str, Any]) -> dict[str, Any]:
    files = get(api, token, f"/repos/{TARGET_REPOSITORY}/pulls/{current['number']}/files?per_page=100&page=1")
    if not isinstance(files, list) or len(files) != current["changed_files"] or not files or len(files) > MAX_FILES:
        raise Refusal("changed-file list is unavailable or outside bounds")
    old_tree, new_tree = tree(api, token, current["base"]), tree(api, token, current["head"])
    total, seen, result = 0, set(), []
    for item in files:
        if not isinstance(item, dict):
            raise Refusal("malformed changed-file record")
        filename, status = source_path(item.get("filename")), item.get("status")
        previous = source_path(item.get("previous_filename")) if item.get("previous_filename") is not None else filename
        if filename in seen or status not in {"added", "modified", "removed", "renamed", "copied", "changed"}:
            raise Refusal("unsafe changed-file metadata")
        seen.add(filename)
        old_entry, new_entry = (None if status == "added" else old_tree.get(previous)), (None if status == "removed" else new_tree.get(filename))
        if (status != "added" and old_entry is None) or (status != "removed" and new_entry is None):
            raise Refusal("changed file is absent from declared tree")
        for entry in (old_entry, new_entry):
            if entry is not None and (entry["type"] != "blob" or entry["mode"] not in {"100644", "100755"}):
                raise Refusal("symlink, submodule, or unsupported mode is out of bounds")
        if new_entry is not None and new_entry["sha"] != sha(item.get("sha")):
            raise Refusal("changed-file list and head tree disagree")
        old, new = "" if old_entry is None else blob(api, token, old_entry["sha"]), "" if new_entry is None else blob(api, token, new_entry["sha"])
        total += len(old.encode("utf-8")) + len(new.encode("utf-8"))
        if total > MAX_TOTAL_BYTES:
            raise Refusal("combined source exceeds safe review bounds")
        diff = "".join(difflib.unified_diff(old.splitlines(keepends=True), new.splitlines(keepends=True), fromfile=f"a/{previous}", tofile=f"b/{filename}"))
        result.append({"path": filename, "previous_path": previous if previous != filename else None, "status": status, "base_text": old, "head_text": new, "diff": diff})
    payload = {"schema": "ads.external-bootstrap.material.v1", "identity": current, "files": result}
    if len(compact(payload).encode("utf-8")) > MAX_REVIEW_REQUEST_BYTES:
        raise Refusal("review request exceeds bounded Claude context")
    return payload


def write_output(material_output: dict[str, Any] | None, reason: str) -> None:
    output = os.environ.get("GITHUB_OUTPUT")
    if not output:
        raise Refusal("GitHub Actions output path is unavailable")
    encoded = "" if material_output is None else compact(material_output)
    if len(encoded.encode("utf-8")) > MAX_REVIEW_REQUEST_BYTES:
        raise Refusal("material output exceeds safe bound")
    clean_reason = reason.replace("\r", " ").replace("\n", " ")[:2000]
    with Path(output).open("a", encoding="utf-8") as handle:
        handle.write("material=" + encoded + "\n")
        handle.write("reason=" + clean_reason + "\n")


def same_current(api: str, token: str, number: int, expected: dict[str, Any]) -> bool:
    try:
        return identity(api, token, number) == expected
    except Refusal:
        return False


def run(args: argparse.Namespace) -> int:
    material_output: dict[str, Any] | None = None
    reason = ""
    try:
        event = strict_json(Path(args.event_path).read_text(encoding="utf-8"), "workflow event")
        if not isinstance(event, dict):
            raise Refusal("workflow event must be an object")
        number, event_head, event_base = event_identity(event, args.pull_number)
        expected_head = sha(args.expected_head)
        api, token = os.environ.get("GITHUB_API_URL", "https://api.github.com"), os.environ.get("GITHUB_TOKEN", "")
        if not token:
            raise Refusal("read-only GitHub token is unavailable")
        current = identity(api, token, number)
        if current["head"] != expected_head or (event_head is not None and current["head"] != event_head) or (event_base is not None and current["base"] != event_base):
            raise Refusal("workflow event is stale")
        material_output = material(api, token, current)
        if not same_current(api, token, number, current):
            raise Refusal("pull request changed while source was collected")
    except Refusal as error:
        material_output, reason = None, str(error)
    write_output(material_output, reason)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--event-path", required=True)
    parser.add_argument("--pull-number", default="")
    parser.add_argument("--expected-head", required=True)
    return run(parser.parse_args())


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Refusal as error:
        print(f"external evaluator refused: {error}", file=sys.stderr)
        raise SystemExit(2)
