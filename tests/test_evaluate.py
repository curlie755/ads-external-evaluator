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
        manual = {"repository": {"full_name": evaluator.TARGET_REPOSITORY}}
        self.assertEqual(evaluator.event_identity(manual, "43"), (43, None, None))
        for value in ("43; id", "01", "-1", "０１"):
            with self.assertRaises(evaluator.Refusal):
                evaluator.event_identity(manual, value)

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

    def test_stale_expected_head_emits_no_material(self):
        current = self.identity()
        event = {"repository": {"full_name": evaluator.TARGET_REPOSITORY}, "number": 43, "pull_request": {"head": {"sha": current["head"]}, "base": {"sha": current["base"], "ref": "main"}}}
        with tempfile.TemporaryDirectory() as directory:
            event_path, output_path = Path(directory) / "event.json", Path(directory) / "output.txt"
            event_path.write_text(json.dumps(event), encoding="utf-8")
            args = SimpleNamespace(event_path=str(event_path), pull_number="", expected_head="d" * 40)
            with mock.patch.dict(os.environ, {"GITHUB_TOKEN": "read", "GITHUB_OUTPUT": str(output_path)}, clear=True), mock.patch.object(evaluator, "identity", return_value=current), mock.patch.object(evaluator, "material") as collect:
                self.assertEqual(evaluator.run(args), 0)
            values = dict(line.split("=", 1) for line in output_path.read_text(encoding="utf-8").splitlines())
        self.assertEqual(values["material"], "")
        self.assertIn("stale", values["reason"])
        collect.assert_not_called()

    def test_success_returns_identity_bound_material(self):
        current = self.identity()
        event = {"repository": {"full_name": evaluator.TARGET_REPOSITORY}, "number": 43, "pull_request": {"head": {"sha": current["head"]}, "base": {"sha": current["base"], "ref": "main"}}}
        material = {"schema": "ads.external-bootstrap.material.v1", "identity": current, "files": [{"path": "safe.py"}]}
        with tempfile.TemporaryDirectory() as directory:
            event_path, output_path = Path(directory) / "event.json", Path(directory) / "output.txt"
            event_path.write_text(json.dumps(event), encoding="utf-8")
            args = SimpleNamespace(event_path=str(event_path), pull_number="", expected_head=current["head"])
            with mock.patch.dict(os.environ, {"GITHUB_TOKEN": "read", "GITHUB_OUTPUT": str(output_path)}, clear=True), mock.patch.object(evaluator, "identity", return_value=current), mock.patch.object(evaluator, "material", return_value=material), mock.patch.object(evaluator, "same_current", return_value=True):
                self.assertEqual(evaluator.run(args), 0)
            values = dict(line.split("=", 1) for line in output_path.read_text(encoding="utf-8").splitlines())
        self.assertEqual(json.loads(values["material"]), material)
        self.assertEqual(values["reason"], "")

    def test_action_is_checkout_model_and_secret_free(self):
        action = (ROOT / "action.yml").read_text(encoding="utf-8")
        source = (ROOT / "src/evaluate.py").read_text(encoding="utf-8")
        self.assertNotIn("actions/checkout", action)
        self.assertNotIn("CLAUDE_CODE_OAUTH_TOKEN", source)
        self.assertIn('TARGET_REPOSITORY = "curlie755/agentic-development-harness"', source)
        self.assertNotIn("CROSS_VENDOR_APP_PRIVATE_KEY", source)
        self.assertNotIn("subprocess", source)
        self.assertNotIn("claude-bin", action + source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
