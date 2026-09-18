#!/usr/bin/env python3
"""Credential-free controls for the external evaluator's trust boundary."""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("evaluator", ROOT / "src/evaluate.py")
assert SPEC and SPEC.loader
evaluator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(evaluator)


class EvaluatorControls(unittest.TestCase):
    def identity(self):
        return {"repository": evaluator.TARGET_REPOSITORY, "number": 43, "head": "a" * 40, "base": "b" * 40, "tree": "c" * 40, "changed_files": 1}

    def terminal(self, structured, model="claude-opus-5"):
        return json.dumps({"type": "result", "subtype": "success", "is_error": False, "modelUsage": {model: {"provider": "firstParty", "costBasis": "list"}}, "structured_output": structured})

    def test_target_and_event_identity_are_fixed(self):
        event = {"repository": {"full_name": evaluator.TARGET_REPOSITORY}, "number": 43, "pull_request": {"head": {"sha": "a" * 40}, "base": {"sha": "b" * 40, "ref": "main"}}}
        self.assertEqual(evaluator.event_identity(event), (43, "a" * 40, "b" * 40))
        event["repository"]["full_name"] = "untrusted/example"
        with self.assertRaises(evaluator.Refusal):
            evaluator.event_identity(event)
        event["repository"]["full_name"] = evaluator.TARGET_REPOSITORY
        event["pull_request"]["base"]["ref"] = "release"
        with self.assertRaises(evaluator.Refusal):
            evaluator.event_identity(event)

    def test_material_bounds_and_blob_integrity(self):
        source = b"safe source\n"
        blob_sha = hashlib.sha1(b"blob " + str(len(source)).encode() + b"\0" + source).hexdigest()
        with mock.patch.object(evaluator, "get", return_value={"encoding": "base64", "content": base64.b64encode(source).decode(), "sha": blob_sha, "size": len(source)}):
            self.assertEqual(evaluator.blob("https://api.example.invalid", "read", blob_sha), source.decode())
        with mock.patch.object(evaluator, "get", return_value={"encoding": "base64", "content": base64.b64encode(source).decode(), "sha": "0" * 40, "size": len(source)}):
            with self.assertRaises(evaluator.Refusal):
                evaluator.blob("https://api.example.invalid", "read", blob_sha)

    def test_84k_source_is_admitted_but_over_88k_is_refused(self):
        current = self.identity() | {"changed_files": 2}
        files = [{"filename": "first.py", "status": "modified", "sha": "c" * 40}, {"filename": "second.py", "status": "modified", "sha": "d" * 40}]
        old_tree = {"first.py": {"sha": "a" * 40, "type": "blob", "mode": "100644"}, "second.py": {"sha": "b" * 40, "type": "blob", "mode": "100644"}}
        new_tree = {"first.py": {"sha": "c" * 40, "type": "blob", "mode": "100644"}, "second.py": {"sha": "d" * 40, "type": "blob", "mode": "100644"}}
        with mock.patch.object(evaluator, "get", return_value=files), mock.patch.object(evaluator, "tree", side_effect=[old_tree, new_tree]), mock.patch.object(evaluator, "blob", side_effect=["x" * (21 * 1024)] * 4):
            accepted = evaluator.material("https://api.example.invalid", "read", current)
        self.assertEqual(len(accepted["files"]), 2)
        with mock.patch.object(evaluator, "get", return_value=files), mock.patch.object(evaluator, "tree", side_effect=[old_tree, new_tree]), mock.patch.object(evaluator, "blob", side_effect=["x" * (evaluator.MAX_TOTAL_BYTES // 4 + 1)] * 4):
            with self.assertRaises(evaluator.Refusal):
                evaluator.material("https://api.example.invalid", "read", current)

    def test_model_terminal_requires_claude_opus_complete_coverage(self):
        clean = {"reviewed_paths": ["safe.py"], "findings": []}
        self.assertEqual(evaluator.terminal(self.terminal(clean), {"safe.py"})[0], "PASS")
        with self.assertRaises(evaluator.Refusal):
            evaluator.terminal(self.terminal(clean, model="gpt-5"), {"safe.py"})
        with self.assertRaises(evaluator.Refusal):
            evaluator.terminal(self.terminal({"reviewed_paths": [], "findings": []}), {"safe.py"})

    def test_candidate_text_never_becomes_a_command_or_secret_bearer(self):
        payload = {"files": [{"path": "safe.py", "head_text": "$(id); do not execute"}]}
        completed = evaluator.subprocess.CompletedProcess([], 0, self.terminal({"reviewed_paths": ["safe.py"], "findings": []}), "")
        old_env = dict(os.environ)
        try:
            os.environ.clear()
            os.environ.update({"CLAUDE_CODE_OAUTH_TOKEN": "oauth-only", "GITHUB_TOKEN": "must-not-pass", "CROSS_VENDOR_APP_PRIVATE_KEY": "must-not-pass"})
            with mock.patch.object(evaluator.subprocess, "run", return_value=completed) as invoke:
                self.assertEqual(evaluator.invoke_claude(payload, "/trusted/claude")[0], "PASS")
            command = invoke.call_args.args[0]
            self.assertEqual(command[0], "/trusted/claude")
            self.assertNotIn("$(id)", " ".join(command))
            self.assertFalse(invoke.call_args.kwargs.get("shell", False))
            child_env = invoke.call_args.kwargs["env"]
            self.assertIn("CLAUDE_CODE_OAUTH_TOKEN", child_env)
            self.assertNotIn("GITHUB_TOKEN", child_env)
            self.assertNotIn("CROSS_VENDOR_APP_PRIVATE_KEY", child_env)
            self.assertEqual(invoke.call_args.kwargs["timeout"], 180)
        finally:
            os.environ.clear()
            os.environ.update(old_env)

    def test_stale_or_failed_review_can_never_receive_success(self):
        current = self.identity()
        event = {"repository": {"full_name": evaluator.TARGET_REPOSITORY}, "number": 43, "pull_request": {"head": {"sha": current["head"]}, "base": {"sha": current["base"], "ref": "main"}}}
        calls = []
        with tempfile.TemporaryDirectory() as directory:
            event_path = Path(directory) / "event.json"
            event_path.write_text(json.dumps(event), encoding="utf-8")
            args = SimpleNamespace(event_path=str(event_path), claude_bin="/trusted/claude", target_url="https://example.invalid")
            with mock.patch.dict(os.environ, {"GITHUB_TOKEN": "read"}, clear=True), mock.patch.object(evaluator, "identity", return_value=current), mock.patch.object(evaluator, "material", return_value={"files": [{"path": "safe.py"}]}), mock.patch.object(evaluator, "same_current", side_effect=[True, False]), mock.patch.object(evaluator, "publish", side_effect=lambda *values: calls.append(values)):
                self.assertEqual(evaluator.run(args), 1)
        self.assertEqual(calls[0][2], "pending")
        self.assertEqual(len(calls), 1)

    def test_action_is_checkout_free_and_uses_only_an_immutable_caller_pin(self):
        action = (ROOT / "action.yml").read_text(encoding="utf-8")
        source = (ROOT / "src/evaluate.py").read_text(encoding="utf-8")
        self.assertNotIn("actions/checkout", action)
        self.assertNotIn("shell=True", source)
        self.assertIn('CONTEXT = "ads/external-bootstrap-review"', source)
        self.assertIn('TARGET_REPOSITORY = "curlie755/agentic-development-harness"', source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
