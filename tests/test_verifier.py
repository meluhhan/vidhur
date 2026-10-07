import unittest
import pathlib
import os
import json
import subprocess
import tempfile
from unittest.mock import patch

from vidhur import Vidhur
from reporter import VidhurReporter
from threat_graph import ASSET, INCONCLUSIVE, ThreatGraph
from policy import PolicyError, load_policy
from threat_graph import STATUS_DISPROVEN, STATUS_FAILED, STATUS_UNKNOWN, STATUS_VERIFIED
from verifier import (
    COMMAND_EXECUTION_DISABLED,
    SealedVerifier,
    VerificationResult,
    discover_project_checks,
    discover_test_suites,
)


class AdversarialVerificationTests(unittest.TestCase):
    def setUp(self):
        self.verifier = SealedVerifier()

    def test_nonzero_exit_without_rejection_oracle_is_unknown(self):
        with patch.object(self.verifier, "run_command", return_value=(7, "safe", "", 1.0)):
            result = self.verifier.verify_adversarial("reproducer", cwd="/tmp")

        self.assertEqual(result.verdict, STATUS_UNKNOWN)

    def test_zero_exit_without_rejection_oracle_is_unknown(self):
        with patch.object(self.verifier, "run_command", return_value=(0, "accepted", "", 1.0)):
            result = self.verifier.verify_adversarial("reproducer", cwd="/tmp")

        self.assertEqual(result.verdict, STATUS_UNKNOWN)

    def test_expected_rejection_pattern_can_accept_nonzero_exit(self):
        with patch.object(self.verifier, "run_command", return_value=(2, "input rejected", "", 1.0)):
            result = self.verifier.verify_adversarial(
                "reproducer",
                expected_rejection_pattern="input rejected",
                cwd="/tmp",
            )

        self.assertEqual(result.verdict, STATUS_VERIFIED)

    def test_traceback_is_not_automatically_a_security_crash(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            vidhur = Vidhur(cache_dir=str(pathlib.Path(temp_dir) / "cache"), target_dir=temp_dir)
            with patch.object(
                vidhur.verifier,
                "run_command",
                return_value=(1, "Traceback (most recent call last): ValueError", "", 1.0),
            ):
                result = vidhur.verify_crash("ordinary-error", "reproducer")

        self.assertEqual(result["verdict"], STATUS_UNKNOWN)


class TargetGraphIsolationTests(unittest.TestCase):
    def test_custom_cache_root_is_namespaced_by_target(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            cache_root = root / "cache"
            target_a = Vidhur(cache_dir=str(cache_root), target_dir=str(root / "a"))
            target_a.graph.record_finding(
                "Target A finding", "test", "L2_BUG_WITNESS", {"oracle": "test"}
            )
            target_a.graph.save()

            target_b = Vidhur(cache_dir=str(cache_root), target_dir=str(root / "b"))

            self.assertEqual(target_b.graph.get_verified_findings(), [])


class EngagementPolicyTests(unittest.TestCase):
    def write_policy(self, root, target, **overrides):
        policy = {
            "version": 1,
            "target": str(target),
            "revision": "a1b2c3d4",
            "goal": "Find reproducible security defects",
            "crown_jewels": ["customer records"],
            "authorization": {"authorized": False},
            "scope": {"in_scope": ["src/**"], "out_of_scope": ["src/secrets/**"]},
            "execution": {"allow_host_execution": False},
            "forbidden_actions": ["network access"],
            "budget": {"max_commands": 0, "command_timeout_seconds": 20, "total_runtime_seconds": 0},
        }
        policy.update(overrides)
        path = pathlib.Path(root) / "input.md"
        path.write_text("# Rules\n\n```json\n" + json.dumps(policy) + "\n```\n")
        return path

    def test_default_policy_blocks_execution_even_with_cli_opt_in(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            vidhur = Vidhur(target_dir=temp_dir, allow_host_execution=True)

        self.assertFalse(vidhur.verifier.allow_host_execution)
        self.assertIn("do not authorize", vidhur.execution_block_reason)

    def test_authorized_policy_requires_target_and_revision(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            target = pathlib.Path(temp_dir) / "target"
            target.mkdir()
            policy_path = self.write_policy(
                temp_dir,
                target,
                revision="latest",
                authorization={"authorized": True},
                scope={"in_scope": ["src/**"], "out_of_scope": []},
            )

            with self.assertRaisesRegex(PolicyError, "pin revision"):
                load_policy(policy_path)

    def test_execution_requires_policy_and_cli_opt_in_for_exact_target(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            target = root / "target"
            target.mkdir()
            policy_path = self.write_policy(
                root,
                target,
                authorization={"authorized": True},
                scope={"in_scope": ["**"], "out_of_scope": []},
                execution={"allow_host_execution": True},
                budget={"max_commands": 2, "command_timeout_seconds": 7, "total_runtime_seconds": 30},
            )
            allowed = Vidhur(
                target_dir=str(target),
                policy_path=str(policy_path),
                allow_host_execution=True,
            )
            no_cli_opt_in = Vidhur(
                target_dir=str(target),
                policy_path=str(policy_path),
                allow_host_execution=False,
            )
            wrong_target = Vidhur(
                target_dir=str(root),
                policy_path=str(policy_path),
                allow_host_execution=True,
            )

        self.assertIsNone(allowed.execution_block_reason)
        self.assertEqual(allowed.verifier.max_commands, 2)
        self.assertEqual(allowed.verifier.default_timeout_s, 7)
        self.assertEqual(allowed.policy.crown_jewels, ["customer records"])
        self.assertEqual(allowed.policy.forbidden_actions, ["network access"])
        self.assertIn("Pass --allow-host-execution", no_cli_opt_in.execution_block_reason)
        self.assertIn("does not match", wrong_target.execution_block_reason)

    def test_policy_in_scope_and_exclusions_are_enforced_for_observations(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            target = root / "target"
            target.mkdir()
            policy_path = self.write_policy(root, target)
            vidhur = Vidhur(target_dir=str(target), policy_path=str(policy_path))
            node_id = vidhur.observe(ASSET, "API route", "Express route", "src/routes.js")

            with self.assertRaises(PermissionError):
                vidhur.observe(ASSET, "Secret input", "out of scope", "src/secrets/key.js")

        node = vidhur.graph.nodes[node_id]
        self.assertTrue(node.untrusted)
        self.assertEqual(node.data["source"], "target")
        self.assertEqual(node.data["target_revision"], "a1b2c3d4")

    def test_path_escape_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            target = root / "target"
            target.mkdir()
            policy_path = self.write_policy(root, target)
            vidhur = Vidhur(target_dir=str(target), policy_path=str(policy_path))

            with self.assertRaises(ValueError):
                vidhur.observe(ASSET, "Escape", "outside target", "../outside.js")

    def test_iteration_log_requires_complete_entry_and_is_persisted(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            target = pathlib.Path(temp_dir) / "target"
            target.mkdir()
            vidhur = Vidhur(target_dir=str(target))
            with self.assertRaisesRegex(ValueError, "missing fields"):
                vidhur.log_iteration({"iteration": 1})

            result = vidhur.log_iteration({
                "iteration": 1,
                "mode": "MAP",
                "target": "auth route authorization",
                "did": "inspected route middleware",
                "result": "no middleware found in inspected route files",
                "verify": "not executed",
                "next": "inspect deployment authorizer",
            })

            ledger = vidhur.run_log_path.read_text(encoding="utf-8")

        self.assertTrue(result["logged"])
        self.assertIn('"event": "agent_iteration"', ledger)
        self.assertIn('"target_revision": "unspecified"', ledger)


class ThreatGraphMemoryTests(unittest.TestCase):
    def test_inconclusive_memory_is_not_negative_memory(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            graph = ThreatGraph(pathlib.Path(temp_dir) / "graph")
            node = graph.record_inconclusive(
                "input reaches SQL sink",
                "Execution disabled before the check could run",
                scope="commit-a:backend/query.js",
                evidence={"run_id": "run-1"},
            )

        self.assertEqual(node.kind, INCONCLUSIVE)
        self.assertEqual(node.status, STATUS_UNKNOWN)
        self.assertEqual(graph.get_negative_memory(), [])
        self.assertEqual(graph.get_inconclusive_memory()[0].data["evidence"]["run_id"], "run-1")

    def test_question_resolution_requires_structured_evidence(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            graph = ThreatGraph(pathlib.Path(temp_dir) / "graph")
            question = graph.add_question("Does route require auth?", scope="rev-a:backend")

            with self.assertRaisesRegex(ValueError, "structured evidence"):
                graph.resolve_question(question.id, "Yes", evidence={})

            graph.resolve_question(
                question.id,
                "The route uses the auth middleware",
                evidence={"oracle": "source_inspection", "result": "middleware_attached"},
            )

        self.assertEqual(question.status, "RESOLVED")

    def test_disproof_lookup_requires_exact_claim_and_scope(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            graph = ThreatGraph(pathlib.Path(temp_dir) / "graph")
            graph.record_disproof(
                "SQL injection in report route",
                "Prepared statement verified",
                scope="commit-a:backend/report.js",
                evidence={"oracle": "static_check", "result": "prepared_query"},
            )

        self.assertTrue(graph.is_disproven("SQL injection in report route", "commit-a:backend/report.js"))
        self.assertFalse(graph.is_disproven("SQL injection", "commit-a:backend/report.js"))
        self.assertFalse(graph.is_disproven("SQL injection in report route", "commit-b:backend/report.js"))

    def test_disproof_requires_structured_oracle_evidence(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            graph = ThreatGraph(pathlib.Path(temp_dir) / "graph")

            with self.assertRaisesRegex(ValueError, "structured evidence"):
                graph.record_disproof("claim", "the agent thinks it is false")


class PatchStatusTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        root = pathlib.Path(self.temp_dir.name)
        self.vidhur = Vidhur(cache_dir=str(root / "cache"), target_dir=str(root / "target"))
        self.finding = self.vidhur.graph.record_finding(
            "Verified issue", "test finding", "L2_BUG_WITNESS", {"oracle": "test"}
        )

    def test_cannot_mark_patched_without_retest_and_regression_results(self):
        result = self.vidhur.mark_patched(self.finding.id, reverify_log="all passed")

        self.assertFalse(result)
        self.assertEqual(self.finding.status, STATUS_VERIFIED)

    def test_mark_patched_persists_required_verification_results(self):
        verification_results = {
            "layer1": {"verdict": STATUS_VERIFIED},
            "layer2": {"verdict": STATUS_VERIFIED},
        }
        result = self.vidhur.mark_patched(
            self.finding.id,
            verification_results=verification_results,
            reverify_log="reproducer and suite passed",
        )

        self.assertTrue(result)
        self.assertEqual(self.finding.status, "PATCHED")
        self.assertEqual(self.finding.data["verification_results"], verification_results)


class LayerSummaryTests(unittest.TestCase):
    def test_layer_one_is_unknown_without_an_explicit_reproducer(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            vidhur = Vidhur(cache_dir=str(pathlib.Path(temp_dir) / "cache"), target_dir=temp_dir)
            with patch.object(vidhur, "verify_layer2_tests", return_value={"verdict": "VERIFIED"}), \
                    patch.object(vidhur, "verify_layer3_types", return_value={"verdict": "VERIFIED"}), \
                    patch.object(vidhur, "verify_layer4_devops", return_value={"verdict": "VERIFIED"}):
                results = vidhur.verify_all_layers()

        self.assertEqual(results["layer1"], STATUS_UNKNOWN)
        self.assertIn("layer1_reason", results)

    def test_report_without_layer_results_is_incomplete(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            graph = ThreatGraph(root / "cache")
            report = VidhurReporter(graph, root / "report.md").generate_report()

        self.assertIn("| Audit Status | `INCOMPLETE` |", report)
        self.assertIn("Layer 1: Adversarial Re-Testing | `UNKNOWN`", report)

    def test_report_excludes_memory_from_other_revisions(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            graph = ThreatGraph(root / "cache")
            graph.add_hypothesis("revision A issue", "old", scope="revision-a:src/app.js")
            graph.add_hypothesis("revision B issue", "current", scope="revision-b:src/app.js")
            report = VidhurReporter(graph, root / "report.md").generate_report(
                scope_prefix="revision-b:"
            )

        self.assertIn("revision B issue", report)
        self.assertNotIn("revision A issue", report)

    def test_report_discloses_policy_provenance(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            graph = ThreatGraph(root / "cache")
            report = VidhurReporter(graph, root / "report.md").generate_report(
                assessment_context={
                    "run_id": "run-123",
                    "target_revision": "abc123",
                    "policy_sha256": "deadbeef",
                    "execution_authorized": False,
                    "goal": "Check auth boundary",
                    "crown_jewels": ["customer data"],
                    "forbidden_actions": ["network access"],
                    "legacy_entries_excluded": 2,
                }
            )

        self.assertIn("Revision: `abc123`", report)
        self.assertIn("Policy SHA-256: `deadbeef`", report)
        self.assertIn("Goal: Check auth boundary", report)
        self.assertIn("customer data", report)
        self.assertIn("Forbidden actions: network access", report)
        self.assertIn("entries excluded: `2`", report)

    def test_report_lists_open_hypothesis_scope_and_description(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            vidhur = Vidhur(cache_dir=str(root / "cache"), target_dir=str(root / "target"))
            vidhur.hypothesize(
                "Check route authorization",
                "Confirm report routes enforce user-level ownership.",
                scope="backend/routes/reportRoutes.js",
            )
            report = VidhurReporter(vidhur.graph, root / "report.md").generate_report()

        self.assertIn("Check route authorization", report)
        self.assertIn("backend/routes/reportRoutes.js", report)
        self.assertIn("Confirm report routes enforce user-level ownership.", report)
        self.assertIn("These are questions for investigation, not verified findings.", report)

    def test_failed_check_is_not_reported_as_disproven_hypothesis_or_clean(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            graph = ThreatGraph(root / "cache")
            layers = {
                "layer1": STATUS_VERIFIED,
                "layer2": STATUS_FAILED,
                "layer3": STATUS_VERIFIED,
                "layer4": STATUS_VERIFIED,
            }
            report = VidhurReporter(graph, root / "report.md").generate_report(
                verification_layers=layers
            )

        self.assertIn("| Audit Status | `CHECKS_FAILED` |", report)

    def test_report_includes_layer_reason_details(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            graph = ThreatGraph(root / "cache")
            report = VidhurReporter(graph, root / "report.md").generate_report(
                verification_layers={
                    "layer1": STATUS_UNKNOWN,
                    "layer1_reason": "No reproducer supplied",
                    "layer2": STATUS_FAILED,
                    "layer2_reason": "backend npm test exits 1: no test specified",
                    "layer3": STATUS_UNKNOWN,
                    "layer4": STATUS_UNKNOWN,
                }
            )

        self.assertIn("backend npm test exits 1: no test specified", report)
        self.assertIn("No reproducer supplied", report)


class DevOpsVerificationTests(unittest.TestCase):
    def setUp(self):
        self.verifier = SealedVerifier()

    def test_no_supported_artifacts_is_unknown(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            result = self.verifier.verify_devops_ci(temp_dir)

        self.assertEqual(result.verdict, STATUS_UNKNOWN)

    def test_env_example_alone_is_not_reported_as_validated(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            pathlib.Path(temp_dir, ".env.example").write_text("TOKEN=value\n")
            result = self.verifier.verify_devops_ci(temp_dir)

        self.assertEqual(result.verdict, STATUS_UNKNOWN)

    def test_workflow_without_yaml_parser_is_unknown(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            workflow_dir = pathlib.Path(temp_dir, ".github", "workflows")
            workflow_dir.mkdir(parents=True)
            (workflow_dir / "ci.yml").write_text("name: CI\n")
            original_import = __import__

            def import_without_yaml(name, *args, **kwargs):
                if name == "yaml":
                    raise ImportError("PyYAML unavailable")
                return original_import(name, *args, **kwargs)

            with patch("builtins.__import__", side_effect=import_without_yaml):
                result = self.verifier.verify_devops_ci(temp_dir)

        self.assertEqual(result.verdict, STATUS_UNKNOWN)


class HostExecutionOptInTests(unittest.TestCase):
    def test_host_commands_are_disabled_by_default(self):
        verifier = SealedVerifier()
        with patch("verifier.subprocess.Popen") as popen:
            code, _, stderr, _ = verifier.run_command("echo should-not-run", cwd="/tmp")

        self.assertEqual(code, COMMAND_EXECUTION_DISABLED)
        self.assertIn("trusted target code", stderr)
        popen.assert_not_called()

    def test_network_isolation_request_fails_closed(self):
        verifier = SealedVerifier(allow_host_execution=True)
        with patch("verifier.subprocess.Popen") as popen:
            code, _, stderr, _ = verifier.run_command("network-command", cwd="/tmp", isolate_network=True)

        self.assertEqual(code, COMMAND_EXECUTION_DISABLED)
        self.assertIn("Network isolation is not enforced", stderr)
        popen.assert_not_called()

    def test_command_working_directory_must_stay_inside_policy_target(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            target = root / "target"
            target.mkdir()
            outside = root / "outside"
            outside.mkdir()
            verifier = SealedVerifier(
                allow_host_execution=True,
                execution_root=target,
            )
            with patch("verifier.subprocess.Popen") as popen:
                code, _, stderr, _ = verifier.run_command("echo no", cwd=str(outside))

        self.assertEqual(code, COMMAND_EXECUTION_DISABLED)
        self.assertIn("outside the authorized target root", stderr)
        popen.assert_not_called()

    def test_venv_resolution_does_not_provision_by_default(self):
        verifier = SealedVerifier()
        with patch.object(verifier, "provision_cached_venv") as provision:
            verifier.resolve_venv(cwd="/tmp")

        provision.assert_not_called()

    def test_timeout_kills_process_group_and_reaps_process(self):
        verifier = SealedVerifier(allow_host_execution=True)
        process = unittest.mock.Mock(pid=123)
        process.communicate.side_effect = [
            subprocess.TimeoutExpired("long-task", 0.01),
            ("partial output", ""),
        ]
        with patch("verifier.subprocess.Popen", return_value=process) as popen, \
                patch("verifier.os.getpgid", return_value=123), \
                patch("verifier.os.killpg") as killpg:
            code, stdout, stderr, _ = verifier.run_command("long-task", cwd="/tmp", timeout_s=0.01)

        self.assertEqual(code, -999)
        self.assertEqual(stdout, "partial output")
        self.assertIn("timed out", stderr)
        self.assertTrue(killpg.called)
        self.assertTrue(process.communicate.called)
        self.assertTrue(popen.call_args.kwargs["start_new_session"])

    def test_sensitive_environment_variables_are_not_inherited(self):
        verifier = SealedVerifier(allow_host_execution=True)
        with patch.dict(os.environ, {"VIDHUR_TEST_TOKEN": "do-not-leak", "VIDHUR_TEST_LANG": "en"}), \
                patch("verifier.subprocess.Popen") as popen:
            process = popen.return_value
            process.communicate.return_value = ("ok", "")
            verifier.run_command("echo ok", cwd="/tmp")

        child_env = popen.call_args.kwargs["env"]
        self.assertNotIn("VIDHUR_TEST_TOKEN", child_env)
        self.assertEqual(child_env["VIDHUR_TEST_LANG"], "en")

    def test_command_count_budget_is_enforced(self):
        verifier = SealedVerifier(allow_host_execution=True, max_commands=1)
        process = unittest.mock.Mock()
        process.returncode = 0
        process.communicate.return_value = ("ok", "")
        with patch("verifier.subprocess.Popen", return_value=process) as popen:
            first = verifier.run_command("echo first", cwd="/tmp")
            second = verifier.run_command("echo second", cwd="/tmp")

        self.assertEqual(first[0], 0)
        self.assertEqual(second[0], COMMAND_EXECUTION_DISABLED)
        self.assertIn("budget exhausted", second[2])
        self.assertEqual(popen.call_count, 1)

    def test_blocked_test_command_is_unknown(self):
        verifier = SealedVerifier()
        result = verifier.verify_test_suite(cwd="/tmp", custom_test_cmd="test-command")

        self.assertEqual(result.verdict, STATUS_UNKNOWN)

    def test_timed_out_test_command_is_unknown(self):
        verifier = SealedVerifier(allow_host_execution=True)
        with patch.object(verifier, "run_command", return_value=(-999, "", "timed out", 1.0)):
            result = verifier.verify_test_suite(cwd="/tmp", custom_test_cmd="test-command")

        self.assertEqual(result.verdict, STATUS_UNKNOWN)

    def test_failing_test_command_is_failed_not_disproved(self):
        verifier = SealedVerifier(allow_host_execution=True)
        with patch.object(verifier, "run_command", return_value=(1, "test assertion failed", "", 1.0)):
            result = verifier.verify_test_suite(cwd="/tmp", custom_test_cmd="test-command")

        self.assertEqual(result.verdict, STATUS_FAILED)


class StaticVerificationTests(unittest.TestCase):
    def test_no_python_files_is_unknown(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            result = SealedVerifier().verify_static_and_types(temp_dir)

        self.assertEqual(result.verdict, STATUS_UNKNOWN)

    def test_typescript_runs_eslint_and_tsc(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            (root / "src").mkdir()
            (root / "src" / "app.tsx").write_text("export const value = 1;\n")
            (root / "tsconfig.json").write_text('{"compilerOptions":{"noEmit":true}}')
            verifier = SealedVerifier()

            def installed_tool(name):
                return {"eslint": "/tools/eslint", "tsc": "/tools/tsc"}.get(name)

            with patch("verifier.shutil.which", side_effect=installed_tool), \
                    patch.object(verifier, "run_command", return_value=(0, "passed", "", 1.0)) as run_command:
                result = verifier.verify_static_and_types(temp_dir)

        self.assertEqual(result.verdict, STATUS_VERIFIED)
        self.assertEqual(run_command.call_count, 2)
        self.assertIn("ESLint", result.witness.command)
        self.assertIn("TypeScript", result.witness.command)

    def test_typescript_without_config_is_unknown(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            pathlib.Path(temp_dir, "app.ts").write_text("export const value = 1;\n")
            verifier = SealedVerifier()
            with patch("verifier.shutil.which", return_value="/tools/eslint"), \
                    patch.object(verifier, "run_command", return_value=(0, "passed", "", 1.0)):
                result = verifier.verify_static_and_types(temp_dir)

        self.assertEqual(result.verdict, STATUS_UNKNOWN)

    def test_discovers_eslint_in_nested_package(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            frontend = root / "frontend"
            (frontend / "src").mkdir(parents=True)
            (frontend / "node_modules" / ".bin").mkdir(parents=True)
            (frontend / "package.json").write_text('{"scripts":{"lint":"eslint ."}}')
            (frontend / "src" / "app.jsx").write_text("export default function App() { return null; }\n")
            eslint = frontend / "node_modules" / ".bin" / "eslint"
            eslint.touch()
            verifier = SealedVerifier()
            with patch("verifier.shutil.which", return_value=None), \
                    patch.object(verifier, "run_command", return_value=(0, "lint passed", "", 1.0)) as run_command:
                result = verifier.verify_static_and_types(root)

        self.assertEqual(result.verdict, STATUS_VERIFIED)
        self.assertEqual(run_command.call_args.kwargs["cwd"], str(frontend.resolve()))
        self.assertIn(str(eslint), run_command.call_args.args[0])

    def test_missing_static_tools_is_unknown(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            pathlib.Path(temp_dir, "module.py").write_text("value = 1\n")
            with patch("verifier.shutil.which", return_value=None):
                result = SealedVerifier().verify_static_and_types(temp_dir)

        self.assertEqual(result.verdict, STATUS_UNKNOWN)


class TestSuiteDiscoveryTests(unittest.TestCase):
    def test_ignores_placeholder_npm_test_script(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            (root / "package.json").write_text(
                '{"scripts":{"test":"echo \\"Error: no test specified\\" && exit 1"}}'
            )

            suites = discover_test_suites(root)

        self.assertEqual(suites, [])

    def test_discovers_polyglot_suites_in_bounded_monorepo(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            (root / "package.json").write_text('{"scripts":{"test":"jest"}}')
            (root / "tests").mkdir()
            (root / "tests" / "test_app.py").write_text("def test_ok(): pass\n")
            (root / "services" / "api").mkdir(parents=True)
            (root / "services" / "api" / "Cargo.toml").write_text("[package]\nname='api'\n")
            (root / "tools" / "worker").mkdir(parents=True)
            (root / "tools" / "worker" / "go.mod").write_text("module example\n")
            (root / "node_modules" / "ignored").mkdir(parents=True)
            (root / "node_modules" / "ignored" / "Cargo.toml").write_text("[package]\n")

            suites = discover_test_suites(root)

        names = {name for name, _, _ in suites}
        self.assertEqual(names, {"Python tests", "Node.js tests", "Rust tests", "Go tests"})
        self.assertFalse(any("node_modules" in str(package_root) for _, _, package_root in suites))

    def test_runs_every_discovered_test_suite(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            (root / "package.json").write_text('{"scripts":{"test":"jest"}}')
            (root / "services" / "api").mkdir(parents=True)
            (root / "services" / "api" / "go.mod").write_text("module example\n")
            verifier = SealedVerifier()
            with patch.object(
                verifier,
                "run_command",
                side_effect=[(0, "node passed", "", 1.0), (0, "go passed", "", 2.0)],
            ) as run_command:
                result = verifier.verify_test_suite(cwd=temp_dir)

        self.assertEqual(result.verdict, STATUS_VERIFIED)
        self.assertEqual(run_command.call_count, 2)
        self.assertIn("npm test", result.witness.command)
        self.assertIn("go test ./...", result.witness.command)


class ProjectCheckTests(unittest.TestCase):
    def test_discovers_build_and_check_scripts_without_a_test_script(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            package_root = pathlib.Path(temp_dir) / "frontend"
            package_root.mkdir()
            (package_root / "package.json").write_text(
                '{"name":"frontend","scripts":{"build":"vite build","check":"tsc --noEmit"}}'
            )

            checks = discover_project_checks(pathlib.Path(temp_dir))

        self.assertEqual(
            [(name, command) for name, command, _ in checks],
            [("frontend build", "npm run build"), ("frontend check", "npm run check")],
        )

    def test_no_declared_project_checks_is_not_applicable(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            result = SealedVerifier().verify_project_checks(temp_dir)

        self.assertEqual(result.verdict, "NOT_APPLICABLE")

    def test_project_checks_require_execution_opt_in(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            (pathlib.Path(temp_dir) / "package.json").write_text(
                '{"scripts":{"build":"vite build"}}'
            )
            verifier = SealedVerifier()
            with patch.object(
                verifier,
                "run_command",
                return_value=(COMMAND_EXECUTION_DISABLED, "", "disabled", 0.0),
            ) as run_command:
                result = verifier.verify_project_checks(temp_dir)

        self.assertEqual(result.verdict, STATUS_UNKNOWN)
        run_command.assert_called_once()

    def test_project_build_check_is_recorded_separately_from_tests(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            (pathlib.Path(temp_dir) / "package.json").write_text(
                '{"scripts":{"build":"vite build"}}'
            )
            verifier = SealedVerifier(allow_host_execution=True)
            with patch.object(verifier, "run_command", return_value=(0, "build passed", "", 2.0)):
                result = verifier.verify_project_checks(temp_dir)

        self.assertEqual(result.verdict, STATUS_VERIFIED)
        self.assertEqual(result.witness.oracle, "project_checks")
        self.assertIn("npm run build", result.witness.command)

    def test_failed_project_check_marks_audit_checks_failed(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            graph = ThreatGraph(root / "cache")
            report = VidhurReporter(graph, root / "report.md").generate_report(
                verification_layers={
                    "layer1": STATUS_VERIFIED,
                    "layer2": STATUS_UNKNOWN,
                    "layer3": STATUS_VERIFIED,
                    "layer4": "NOT_APPLICABLE",
                    "project_checks": STATUS_FAILED,
                    "project_checks_reason": "frontend build failed",
                }
            )

        self.assertIn("| Audit Status | `CHECKS_FAILED` |", report)
        self.assertIn("frontend build failed", report)

class PythonAssertionTests(unittest.TestCase):
    def setUp(self):
        self.verifier = SealedVerifier()

    def run_assertion_result(self, result_json):
        output = f"VIDHUR_RESULT_START\n{result_json}\nVIDHUR_RESULT_END\n"
        with patch.object(self.verifier, "run_command", return_value=(0, output, "", 1.0)):
            return self.verifier.check_python_assertion("def check(): return True")

    def test_dictionary_without_passed_field_is_unknown(self):
        result = self.run_assertion_result('{"safe": false}')

        self.assertEqual(result.verdict, STATUS_UNKNOWN)

    def test_explicit_false_is_disproven(self):
        result = self.run_assertion_result('{"passed": false}')

        self.assertEqual(result.verdict, STATUS_DISPROVEN)

    def test_verified_witness_contains_replayable_checker_source(self):
        output = "VIDHUR_RESULT_START\n{\"passed\": true}\nVIDHUR_RESULT_END"
        with patch.object(self.verifier, "run_command", return_value=(0, output, "", 1.0)):
            result = self.verifier.check_python_assertion("def check(): return True")

        self.assertEqual(result.verdict, STATUS_VERIFIED)
        self.assertIn(" -c ", result.witness.command)
        self.assertIn("def check(): return True", result.witness.artifacts["python_wrapper"])
        self.assertNotIn("tmp", result.witness.command)

    def test_timeout_is_unknown(self):
        with patch.object(self.verifier, "run_command", return_value=(-999, "", "timed out", 1.0)):
            result = self.verifier.check_python_assertion("def check(): return True")

        self.assertEqual(result.verdict, STATUS_UNKNOWN)

    def test_exception_is_unknown(self):
        with patch.object(self.verifier, "run_command", return_value=(1, "VIDHUR_ERROR_START\nValueError\nVIDHUR_ERROR_END", "", 1.0)):
            result = self.verifier.check_python_assertion("def check(): raise ValueError()")

        self.assertEqual(result.verdict, STATUS_UNKNOWN)

    def test_malformed_result_json_is_unknown(self):
        output = "VIDHUR_RESULT_START\nnot-json\nVIDHUR_RESULT_END"
        with patch.object(self.verifier, "run_command", return_value=(0, output, "", 1.0)):
            result = self.verifier.check_python_assertion("def check(): return True")

        self.assertEqual(result.verdict, STATUS_UNKNOWN)

    def test_unknown_result_does_not_create_negative_memory(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            vidhur = Vidhur(cache_dir=str(pathlib.Path(temp_dir) / "cache"), target_dir=temp_dir)
            unknown = VerificationResult(
                verdict=STATUS_UNKNOWN,
                level="L0_HYPOTHESIS",
                reason="Host execution is disabled",
            )
            with patch.object(vidhur.verifier, "check_python_assertion", return_value=unknown):
                result = vidhur.verify_python("unverified hypothesis", "def check(): return True")

        self.assertEqual(result["verdict"], STATUS_UNKNOWN)
        self.assertEqual(vidhur.graph.get_negative_memory(), [])


class CrashClassificationTests(unittest.TestCase):
    def test_nonzero_command_without_crash_signature_is_unknown(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            vidhur = Vidhur(cache_dir=str(pathlib.Path(temp_dir) / "cache"), target_dir=temp_dir)
            with patch.object(vidhur.verifier, "run_command", return_value=(127, "command not found", "", 1.0)):
                result = vidhur.verify_crash("missing-command", "missing-command")

        self.assertEqual(result["verdict"], STATUS_UNKNOWN)

    def test_sanitizer_signature_records_finding(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            vidhur = Vidhur(cache_dir=str(pathlib.Path(temp_dir) / "cache"), target_dir=temp_dir)
            with patch.object(
                vidhur.verifier,
                "run_command",
                return_value=(1, "", "AddressSanitizer: heap-buffer-overflow", 1.0),
            ):
                result = vidhur.verify_crash("overflow", "reproducer")

        self.assertEqual(result["verdict"], STATUS_VERIFIED)


if __name__ == "__main__":
    unittest.main()