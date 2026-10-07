#!/usr/bin/env python3
"""
vidhur / vidhur.py — unified neurosymbolic security and reliability verification CLI & API.

Supports 4-layer verification across any target directory:
- Layer 1: Adversarial Re-Testing
- Layer 2: Functional & API Test Suites
- Layer 3: Static & Type Analysis
- Layer 4: DevOps & CI/CD Verification
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import sys
import time
import uuid
from typing import Any, Dict, List, Optional

# Local imports
from reporter import VidhurReporter
from policy import EngagementPolicy, PolicyError, load_policy
from threat_graph import (
    ASSET, BOUNDARY, FINDING, HYPOTHESIS, INCONCLUSIVE, INPUT_SOURCE,
    L0_HYPOTHESIS, L2_BUG_WITNESS, SINK,
    STATUS_DISPROVEN, STATUS_PATCHED, STATUS_NOT_APPLICABLE,
    STATUS_VERIFIED, STATUS_UNKNOWN,
    ThreatGraph, UntrustedNodeError,
)
from verifier import SealedVerifier, _detect_crash


class Vidhur:
    def __init__(
        self,
        cache_dir: Optional[str] = None,
        target_dir: Optional[str] = None,
        allow_host_execution: bool = False,
        policy_path: Optional[str] = None,
    ):
        self.target_dir = pathlib.Path(target_dir or os.getcwd()).resolve()
        self.policy: EngagementPolicy = load_policy(policy_path)
        self.run_id = str(uuid.uuid4())
        cache_root = (
            pathlib.Path(cache_dir)
            if cache_dir
            else pathlib.Path.home() / ".cache" / "vidhur" / "graph"
        )
        target_key = hashlib.sha256(str(self.target_dir).encode("utf-8")).hexdigest()[:16]
        self.cache_dir = cache_root / target_key
        self.run_log_path = self.cache_dir / "run_log.jsonl"
        self.execution_block_reason = self.policy.execution_block_reason(
            self.target_dir, cli_opt_in=allow_host_execution
        )
        
        self.graph = ThreatGraph(storage_dir=self.cache_dir)
        self.verifier = SealedVerifier(
            default_timeout_s=self.policy.command_timeout_seconds,
            allow_host_execution=allow_host_execution and self.execution_block_reason is None,
            allow_package_installation=self.policy.allow_package_installation,
            max_commands=self.policy.max_commands,
            max_total_runtime_s=self.policy.total_runtime_seconds,
            execution_block_reason=self.execution_block_reason,
            execution_root=self.target_dir,
    
        )

    def _revision_scope(self, scope: str) -> str:
        return f"{self.policy.revision}:{scope}"

    def _provenance(self, source: str = "agent") -> Dict[str, Any]:
        return {
            "run_id": self.run_id,
            "target": str(self.target_dir),
            "target_revision": self.policy.revision,
            "policy_sha256": self.policy.fingerprint,
            "source": source,
            "recorded_at": time.time(),
        }

    def _require_verifiable(self, name: str, scope: str) -> None:
    """Refuse to verify a hypothesis that is still flagged untrusted."""
    node_id = self.graph._hash_id(HYPOTHESIS, f"{self._revision_scope(scope)}:{name}")
    node = self.graph.nodes.get(node_id)
    if node and node.untrusted:
        raise UntrustedNodeError(
            f"Hypothesis {name!r} derives from untrusted target content. "
            f"Call declassify('{node_id}', evidence) with an independent oracle first."
        )

    def declassify(self, node_id: str, evidence: Dict[str, Any]) -> None:
    """Clear a node's untrusted flag with structured, oracle-backed evidence."""
    self.graph.declassify(
        node_id, {**self._provenance(source="agent_supplied_oracle"), **evidence}
    )
    self.graph.save()
    self._log_event("node_declassified", node_id=node_id, evidence=evidence)

    def _log_event(self, event: str, **data: Any) -> None:
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        record = {"event": event, **self._provenance(), **data}
        with self.run_log_path.open("a", encoding="utf-8") as log_file:
            log_file.write(json.dumps(record, sort_keys=True, default=str) + "\n")

    def log_iteration(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        """Persist one agent-loop iteration in the external JSONL audit ledger."""
        required = {"iteration", "mode", "target", "did", "result", "verify", "next"}
        missing = sorted(required - set(entry))
        if missing:
            raise ValueError(f"Iteration log is missing fields: {', '.join(missing)}")
        self._log_event("agent_iteration", iteration=entry)
        return {"run_id": self.run_id, "logged": True}

    def _record_inconclusive(
        self,
        name: str,
        reason: str,
        scope: str,
        evidence: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        node = self.graph.record_inconclusive(
            hypothesis_name_or_id=name,
            reason=reason,
            scope=self._revision_scope(scope),
            evidence={**self._provenance(source="verifier"), **(evidence or {})},
        )
        self.graph.save()
        self._log_event("verification_inconclusive", memory_id=node.id, name=name, reason=reason)
        return {"verdict": STATUS_UNKNOWN, "reason": reason, "id": node.id}

    def observe(
        self,
        kind: str,
        name: str,
        description: str,
        target_path: str,
        related_node_id: Optional[str] = None,
        relation: str = "relates_to",
    ) -> str:
        """Record a target-derived graph fact, tagged untrusted and scope checked."""
        allowed_kinds = {ASSET, BOUNDARY, INPUT_SOURCE, SINK}
        if kind not in allowed_kinds:
            raise ValueError(f"Observation kind must be one of {sorted(allowed_kinds)}")
        source_path = pathlib.Path(target_path)
        if source_path.is_absolute() or ".." in source_path.parts:
            raise ValueError("Observed target_path must be a safe target-relative path")
        absolute_path = self.target_dir / source_path
        if not self.policy.allows_path(self.target_dir, absolute_path):
            raise PermissionError(f"Observed path is outside policy scope: {target_path}")

        scope = self._revision_scope(source_path.as_posix())
        node = self.graph.add_node(
            kind=kind,
            name=name,
            description=description,
            scope=scope,
            untrusted=True,
            data={**self._provenance(source="target"), "source_path": source_path.as_posix()},
        )
        if related_node_id:
            if related_node_id not in self.graph.nodes:
                raise ValueError(f"Unknown related node id: {related_node_id}")
            self.graph.add_edge(node.id, related_node_id, kind=relation)
        self.graph.save()
        self._log_event("target_observation", node_id=node.id, kind=kind, name=name, path=source_path.as_posix())
        return node.id

    def ask(self, question: str, about: Optional[str] = None, scope: str = "global") -> str:
        related_id = about if about in self.graph.nodes else None
        if about and related_id is None:
            related = next(
                (
                    node for node in self.graph.nodes.values()
                    if node.name.strip().lower() == about.strip().lower()
                    and node.scope.startswith(f"{self.policy.revision}:")
                ),
                None,
            )
            related_id = related.id if related else None
        node = self.graph.add_question(
            question=question,
            scope=self._revision_scope(scope),
            about=related_id,
            provenance=self._provenance(source="agent"),
        )
        self.graph.save()
        self._log_event("question_opened", question_id=node.id, question=question, about=about)
        return node.id

    def resolve_question(self, question_id: str, answer: str, evidence: Dict[str, Any]) -> bool:
        node = self.graph.nodes.get(question_id)
        if node is None or not node.scope.startswith(f"{self.policy.revision}:"):
            return False
        resolution_evidence = {**self._provenance(source="agent_supplied_oracle"), **evidence}
        self.graph.resolve_question(question_id, answer, resolution_evidence)
        self.graph.save()
        self._log_event("question_resolved", question_id=question_id, answer=answer, evidence=resolution_evidence)
        return True

    def hypothesize(
    self,
    name: str,
    description: str,
    target_sink: Optional[str] = None,
    scope: str = "global",
    derived_from: Optional[List[str]] = None,
) -> str:
    node = self.graph.add_hypothesis(
        name=name, description=description,
        target_sink=target_sink,
        scope=self._revision_scope(scope),
        derived_from=derived_from,
    )
    node.data.update(self._provenance())
    self.graph.save()
    self._log_event(
        "hypothesis_recorded",
        hypothesis_id=node.id, name=name, scope=node.scope, untrusted=node.untrusted,
    )
    return node.id

    def verify_crash(
    self,
    name: str,
    cmd: str,
    description: str = "",
    input_payload: Optional[str] = None,
    expected_crash_pattern: Optional[str] = None,
    severity: str = "High",
    cvss: str = "N/A",
    location: str = "N/A",
    scope: str = "global",
) -> Dict[str, Any]:
    self._require_verifiable(name, scope)

    res = self.verifier.run_command(cmd=cmd, cwd=str(self.target_dir), input_data=input_payload)
    code, stdout, stderr, dur = res
    combined = f"{stdout}\n{stderr}"

    crash_sig = _detect_crash(code, stdout, stderr)

    if expected_crash_pattern:
        import re
        m = re.search(expected_crash_pattern, combined, re.IGNORECASE)
        if m:
            crash_sig = m.group(0)
        elif crash_sig or code != 0:
            return self._record_inconclusive(
                name,
                "Execution failed without the expected crash signature",
                scope,
                {"command": cmd, "exit_code": code, "output_hash": self.verifier._hash_output(combined)},
            )

    if code < 0:
        return self._record_inconclusive(
            name,
            f"Verification command did not complete (exit code {code})",
            scope,
            {"command": cmd, "exit_code": code, "output_hash": self.verifier._hash_output(combined)},
        )

    if crash_sig:
        from verifier import VerificationWitness
        witness = VerificationWitness(
            oracle="sanitizer_crash",
            command=cmd,
            exit_code=code,
            duration_ms=dur,
            output_hash=self.verifier._hash_output(combined),
            signature=crash_sig,
            reproducer_input=input_payload[:500] if input_payload else None,
        )
        node = self.graph.record_finding(
            name=name,
            description=description or f"Crash triggered by: {cmd}",
            level=L2_BUG_WITNESS,
            witness=witness.to_dict(),
            scope=self._revision_scope(scope),
            data={"severity": severity, "cvss": cvss, "location": location},
        )
        node.data.update(self._provenance(source="verifier"))
        self.graph.save()
        self._log_event("finding_verified", finding_id=node.id, name=name, witness=node.witness)
        return {"verdict": STATUS_VERIFIED, "id": node.id, "witness": node.witness}

    if code != 0:
        return self._record_inconclusive(
            name,
            f"Nonzero exit code {code} without a recognized crash signature",
            scope,
            {"command": cmd, "exit_code": code, "output_hash": self.verifier._hash_output(combined)},
        )

    # Clean exit is NOT a disproof. The bug may simply not have been triggered.
    return self._record_inconclusive(
        name,
        "Target executed cleanly; hypothesis not confirmed nor disproven",
        scope,
        {
            "command": cmd,
            "exit_code": 0,
            "output_hash": self.verifier._hash_output(combined),
            "note": "clean exit does not prove absence of the hypothesized bug",
        },
    )

        from verifier import SANITIZER_PATTERNS
        import re
        crash_found = False
        matched_sig = None
        for pattern in SANITIZER_PATTERNS:
            m = re.search(pattern, combined, re.IGNORECASE)
            if m:
                crash_found = True
                matched_sig = m.group(0)
                break

        if code < 0:
            return self._record_inconclusive(
                name,
                f"Verification command did not complete (exit code {code})",
                scope,
                {"command": cmd, "exit_code": code, "output_hash": self.verifier._hash_output(combined)},
            )

        if expected_crash_pattern:
            expected_match = re.search(expected_crash_pattern, combined, re.IGNORECASE)
            if expected_match:
                crash_found = True
                matched_sig = expected_match.group(0)
            elif crash_found or code != 0:
                return self._record_inconclusive(
                    name,
                    "Execution failed without the expected crash signature",
                    scope,
                    {"command": cmd, "exit_code": code, "output_hash": self.verifier._hash_output(combined)},
                )

        if crash_found:
            sig_text = matched_sig or f"Non-zero exit code: {code}"
            from verifier import VerificationWitness
            witness = VerificationWitness(
                oracle="sanitizer_crash",
                command=cmd,
                exit_code=code,
                duration_ms=dur,
                output_hash=self.verifier._hash_output(combined),
                signature=sig_text,
                reproducer_input=input_payload[:500] if input_payload else None,
            )
            node = self.graph.record_finding(
                name=name,
                description=description or f"Crash triggered by: {cmd}",
                level=L2_BUG_WITNESS,
                witness=witness.to_dict(),
                scope=self._revision_scope(scope),
                data={"severity": severity, "cvss": cvss, "location": location},
            )
            node.data.update(self._provenance(source="verifier"))
            self.graph.save()
            self._log_event("finding_verified", finding_id=node.id, name=name, witness=node.witness)
            return {"verdict": STATUS_VERIFIED, "id": node.id, "witness": node.witness}
        elif code != 0:
            return self._record_inconclusive(
                name,
                f"Nonzero exit code {code} without a recognized crash signature",
                scope,
                {"command": cmd, "exit_code": code, "output_hash": self.verifier._hash_output(combined)},
            )
        else:
            self.graph.record_disproof(
                hypothesis_name_or_id=name,
                reason="Target executed cleanly without crash or sanitizer alert (exit 0)",
                scope=self._revision_scope(scope),
                evidence={
                    **self._provenance(source="verifier"),
                    "oracle": "target_process",
                    "result": "exit_code_0_without_crash_signature",
                    "command": cmd,
                    "output_sha256": self.verifier._hash_output(combined),
                },
            )
            self.graph.save()
            self._log_event("hypothesis_disproven", name=name, scope=self._revision_scope(scope))
            return {"verdict": STATUS_DISPROVEN, "reason": "Target executed cleanly (exit 0)"}

    def verify_python(
        self,
        name: str,
        code_snippet: str,
        description: str = "",
        entry_func: str = "check",
        severity: str = "High",
        cvss: str = "N/A",
        location: str = "N/A",
        scope: str = "global",
    ) -> Dict[str, Any]:
        res = self.verifier.check_python_assertion(
            code_snippet=code_snippet,
            entry_func=entry_func,
            cwd=str(self.target_dir),
        )
        if res.verdict == STATUS_VERIFIED:
            node = self.graph.record_finding(
                name=name,
                description=description,
                level=res.level,
                witness=res.witness.to_dict() if res.witness else {},
                scope=self._revision_scope(scope),
                data={"severity": severity, "cvss": cvss, "location": location},
            )
            node.data.update(self._provenance(source="verifier"))
            self.graph.save()
            self._log_event("finding_verified", finding_id=node.id, name=name, witness=node.witness)
            return {"verdict": STATUS_VERIFIED, "id": node.id, "witness": node.witness}
        if res.verdict == STATUS_DISPROVEN:
            self.graph.record_disproof(
                hypothesis_name_or_id=name,
                reason=res.reason,
                scope=self._revision_scope(scope),
                evidence={
                    **self._provenance(source="verifier"),
                    "oracle": "python_assertion",
                    "result": "false",
                    "output_sha256": self.verifier._hash_output(f"{res.stdout}\n{res.stderr}"),
                },
            )
            self.graph.save()
        elif res.verdict == STATUS_UNKNOWN:
            return self._record_inconclusive(
                name,
                res.reason,
                scope,
                {"layer": res.layer, "stdout": res.stdout, "stderr": res.stderr},
            )
        self._log_event("verification_result", name=name, verdict=res.verdict, reason=res.reason)
        return {"verdict": res.verdict, "reason": res.reason}

    # ── Multi-Layer Post-Patch Verification ─────────────────────────────────────

    def verify_layer1_adversarial(
    self,
    reproducer_cmd: str,
    oracle_name: str,
    input_payload: Optional[str] = None,
) -> Dict[str, Any]:
    oracle = self.policy.find_adversarial_oracle(oracle_name)
    if oracle is None:
        raise PolicyError(f"No such adversarial oracle in ROE: {oracle_name!r}")
    res = self.verifier.verify_adversarial(
        reproducer_cmd=reproducer_cmd,
        oracle=oracle,
        input_payload=input_payload,
        cwd=str(self.target_dir),
    )
    if res.verdict == STATUS_UNKNOWN:
        self._record_inconclusive(
            "Adversarial re-test: " + reproducer_cmd,
            res.reason,
            "adversarial_retest",
            {"command": reproducer_cmd, "oracle": oracle_name},
        )
    else:
        self._log_event(
            "adversarial_result",
            verdict=res.verdict, reason=res.reason, oracle=oracle_name,
        )
    return res.to_dict()

    def verify_layer2_tests(self, custom_cmd: Optional[str] = None) -> Dict[str, Any]:
        res = self.verifier.verify_test_suite(cwd=str(self.target_dir), custom_test_cmd=custom_cmd)
        return res.to_dict()

    def verify_layer3_types(self) -> Dict[str, Any]:
        res = self.verifier.verify_static_and_types(cwd=str(self.target_dir))
        return res.to_dict()

    def verify_layer4_devops(self) -> Dict[str, Any]:
        res = self.verifier.verify_devops_ci(cwd=str(self.target_dir))
        return res.to_dict()

    def verify_all_layers(self) -> Dict[str, Any]:
        """Runs automatic layers; adversarial verification requires an explicit reproducer."""
        l2 = self.verify_layer2_tests()
        l3 = self.verify_layer3_types()
        l4 = self.verify_layer4_devops()
        project_checks = self.verifier.verify_project_checks(cwd=str(self.target_dir)).to_dict()
        results = {
            "layer1": STATUS_UNKNOWN,
            "layer1_reason": "No adversarial reproducer was supplied",
            "layer2": l2.get("verdict", "UNKNOWN"),
            "layer2_reason": l2.get("reason", "No test result details available"),
            "layer3": l3.get("verdict", "UNKNOWN"),
            "layer3_reason": l3.get("reason", "No static-analysis result details available"),
            "layer4": l4.get("verdict", "UNKNOWN"),
            "layer4_reason": l4.get("reason", "No DevOps result details available"),
            "project_checks": project_checks.get("verdict", STATUS_NOT_APPLICABLE),
            "project_checks_reason": project_checks.get("reason", "No project check details available"),
        }
        self._log_event("layer_results", results=results)
        return results

    def disprove(
        self,
        name_or_id: str,
        reason: str,
        evidence: Dict[str, Any],
        scope: str = "global",
    ) -> None:
        """Record an oracle-backed disproof; agent reasoning alone is insufficient."""
        self.graph.record_disproof(
            hypothesis_name_or_id=name_or_id,
            reason=reason,
            scope=self._revision_scope(scope),
            evidence={**self._provenance(source="agent_supplied_oracle"), **evidence},
        )
        self.graph.save()
        self._log_event("hypothesis_disproven", name=name_or_id, reason=reason, scope=self._revision_scope(scope))

    def mark_patched(
        self,
        finding_id_or_name: str,
        patch_diff: str = "",
        reverify_log: str = "",
        verification_results: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> bool:
        """Mark a finding patched only after its reproducer and regression suite pass."""
        verification_results = verification_results or {}
        required_layers = ("layer1", "layer2")
        if any(
            verification_results.get(layer, {}).get("verdict") != STATUS_VERIFIED
            for layer in required_layers
        ):
            return False

        target_node = None
        for n in self.graph.nodes.values():
            if n.kind == FINDING and (
                n.id == finding_id_or_name or n.name.lower() == finding_id_or_name.lower()
            ):
                target_node = n
                break

        if not target_node:
            return False

        target_node.status = STATUS_PATCHED
        target_node.data["verification_results"] = verification_results
        if patch_diff:
            target_node.data["patch_diff"] = patch_diff
        if reverify_log:
            target_node.data["reverify_log"] = reverify_log
        self.graph.save()
        return True

    def report(self, project_name: str = "Target Project", output_path: Optional[str] = None) -> str:
        out_file = pathlib.Path(output_path) if output_path else self.target_dir / "VIDHUR_REPORT.md"
        layers = self.verify_all_layers()
        reporter = VidhurReporter(graph=self.graph, output_path=out_file)
        report = reporter.generate_report(
            project_name=project_name,
            scope_desc=str(self.target_dir),
            verification_layers=layers,
            scope_prefix=f"{self.policy.revision}:",
            assessment_context={
                **self._provenance(source="policy"),
                "execution_authorized": self.execution_block_reason is None,
                "scope_prefix": f"{self.policy.revision}:",
                "goal": self.policy.goal,
                "crown_jewels": self.policy.crown_jewels,
                "forbidden_actions": self.policy.forbidden_actions,
                "legacy_entries_excluded": sum(
                    1 for node in self.graph.nodes.values()
                    if not node.scope.startswith(f"{self.policy.revision}:")
                ),
            },
        )
        self._log_event("report_generated", output=str(out_file))
        return report

    def summary(self) -> Dict[str, Any]:
        return {
            "open_hypotheses": [n.name for n in self.graph.get_open_hypotheses(scope_prefix=f"{self.policy.revision}:")],
            "verified_findings": [n.name for n in self.graph.get_verified_findings(scope_prefix=f"{self.policy.revision}:")],
            "negative_memory_count": len(self.graph.get_negative_memory(scope_prefix=f"{self.policy.revision}:")),
            "inconclusive_count": len(self.graph.get_inconclusive_memory(scope_prefix=f"{self.policy.revision}:")),
            "open_questions": [
                node.description
                for node in self.graph.get_open_questions(scope_prefix=f"{self.policy.revision}:")
            ], 
            "run_id": self.run_id,
            "target_revision": self.policy.revision,
            "policy_sha256": self.policy.fingerprint,
            "execution_authorized": self.execution_block_reason is None,
            "run_log": str(self.run_log_path),
            "untrusted_open_hypotheses": [
    n.name for n in self.graph.get_open_hypotheses(scope_prefix=f"{self.policy.revision}:")
    if n.untrusted
],
        }


def main():
    parser = argparse.ArgumentParser(description="Vidhur Multi-Layer Verification Engine")
    parser.add_argument("--target", default=".", help="Target project directory path")
    parser.add_argument("--cache", default=None, help="Custom cache directory")
    parser.add_argument("--policy", default=None, help="Rules-of-engagement input.md path")
    parser.add_argument(
        "--allow-host-execution",
        action="store_true",
        help="Allow commands to run on this host; use only with trusted target code",
    )
    
    subparsers = parser.add_subparsers(dest="command")

    # report command
    p_rep = subparsers.add_parser("report", help="Generate VIDHUR_REPORT.md for target")
    p_rep.add_argument("--project", default="Target Project", help="Target project name")
    p_rep.add_argument("--output", default=None, help="Output markdown path")

    # verify-layers command
    subparsers.add_parser("verify-layers", help="Run 4-layer verification on target")

    # status command
    subparsers.add_parser("status", help="Print summary of threat graph and findings")

    args = parser.parse_args()
    v = Vidhur(
        cache_dir=args.cache,
        target_dir=args.target,
        allow_host_execution=args.allow_host_execution,
        policy_path=args.policy,
    )

    if args.command == "report":
        path = v.report(project_name=args.project, output_path=args.output)
        print(f"Report written to: {args.output or (v.target_dir / 'VIDHUR_REPORT.md')}")
    elif args.command == "verify-layers":
        results = v.verify_all_layers()
        print(json.dumps(results, indent=2))
    elif args.command == "status":
        print(json.dumps(v.summary(), indent=2))
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
