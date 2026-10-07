"""
vidhur / reporter — renders and updates VIDHUR_REPORT.md with 4-layer verification details.
"""
from __future__ import annotations

import datetime
import pathlib
from typing import Any, Dict, List, Optional

from threat_graph import (
    FINDING,
    PRIMITIVE,
    STATUS_DISPROVEN,
    STATUS_FAILED,
    STATUS_NOT_APPLICABLE,
    STATUS_PATCHED,
    STATUS_VERIFIED,
    ThreatGraph,
)


class VidhurReporter:
    def __init__(self, graph: ThreatGraph, output_path: Optional[pathlib.Path] = None):
        self.graph = graph
        self.output_path = output_path or pathlib.Path("VIDHUR_REPORT.md")

    def generate_report(
        self,
        project_name: str = "Target Project",
        scope_desc: str = "Full Workspace",
        verification_layers: Optional[Dict[str, Any]] = None,
        assessment_context: Optional[Dict[str, Any]] = None,
        scope_prefix: Optional[str] = None,
    ) -> str:
        verified_findings = self.graph.get_verified_findings(scope_prefix=scope_prefix)
        negative_memory = self.graph.get_negative_memory(scope_prefix=scope_prefix)
        open_hypotheses = self.graph.get_open_hypotheses(scope_prefix=scope_prefix)
        open_questions = self.graph.get_open_questions(scope_prefix=scope_prefix)
        inconclusive_memory = self.graph.get_inconclusive_memory(scope_prefix=scope_prefix)
        layers = verification_layers or {}
        assessment = assessment_context or {}
        layer_statuses = [
            layers.get(key, "UNKNOWN")
            for key in ("layer1", "layer2", "layer3", "layer4", "project_checks")
        ]

        total_tested = len(verified_findings) + len(negative_memory)
        patched_count = sum(1 for f in verified_findings if f.status == STATUS_PATCHED)
        active_vulns = len(verified_findings) - patched_count
        if active_vulns:
            audit_status = "REMEDIATION_NEEDED"
        elif STATUS_FAILED in layer_statuses:
            audit_status = "CHECKS_FAILED"
        elif open_hypotheses or not all(
            status in ("VERIFIED", STATUS_NOT_APPLICABLE) for status in layer_statuses
        ):
            audit_status = "INCOMPLETE"
        else:
            audit_status = "VERIFIED_CLEAN"

        now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        doc = []
        doc.append(f"# Vidhur Security & Reliability Audit Report\n")
        doc.append(f"> Generated: `{now_str}` | Engine: Vidhur Verifier | Scope: `{scope_desc}`\n")
        if assessment:
            doc.append(
                "> Run: `{}` | Revision: `{}` | Policy SHA-256: `{}` | Host execution authorized: `{}`\n".format(
                    assessment.get("run_id", "unknown"),
                    assessment.get("target_revision", "unspecified"),
                    assessment.get("policy_sha256", "unknown"),
                    assessment.get("execution_authorized", False),
                )
            )
            doc.append(
                "> Goal: {} | Crown jewels: {} | Out-of-scope legacy graph entries excluded: `{}`\n".format(
                    assessment.get("goal") or "unspecified",
                    ", ".join(assessment.get("crown_jewels", [])) or "unspecified",
                    assessment.get("legacy_entries_excluded", 0),
                )
            )
            forbidden = assessment.get("forbidden_actions", [])
            if forbidden:
                doc.append(f"> Forbidden actions: {', '.join(forbidden)}\n")
        doc.append("---\n")

        # ── 1. Executive Summary ───────────────────────────────────────────────
        doc.append("## 1. Executive Summary\n")
        doc.append("| Metric | Value |")
        doc.append("| :--- | :--- |")
        doc.append(f"| Target | `{project_name}` |")
        doc.append(f"| Total Hypotheses Formulated | `{total_tested + len(open_hypotheses)}` |")
        doc.append(f"| Open Assessment Questions | `{len(open_questions)}` |")
        doc.append(f"| Machine-Verified Findings (L2+) | `{len(verified_findings)}` |")
        doc.append(f"| Active Unpatched Issues | `{active_vulns}` |")
        doc.append(f"| Verified Patched Issues | `{patched_count}` |")
        doc.append(f"| Disproven Dead Ends (Negative Memory) | `{len(negative_memory)}` |")
        doc.append(f"| Inconclusive Checks | `{len(inconclusive_memory)}` |")
        doc.append(f"| Audit Status | `{audit_status}` |\n")

        # ── 2. Multi-Layer Verification Status ─────────────────────────────────
        doc.append("## 2. Multi-Layer Verification Status\n")
        doc.append("| Verification Layer | Status | Oracle / Details |")
        doc.append("| :--- | :--- | :--- |")
        layer_rows = [
            ("layer1", "Layer 1: Adversarial Re-Testing", "Exploit witness neutralization checks"),
            ("layer2", "Layer 2: Functional & API Tests", "Project test suite & endpoint contracts"),
            ("layer3", "Layer 3: Static & Type Analysis", "AST parsing, typecheckers & linters"),
            ("layer4", "Layer 4: DevOps & CI/CD Check", "Dockerfile and workflow syntax checks"),
            ("project_checks", "Project Checks: Build & Validation", "Declared package checks; not a substitute for tests"),
        ]
        for key, label, default_detail in layer_rows:
            detail = layers.get(f"{key}_reason") or default_detail
            detail = str(detail).replace("|", "\\|").replace("\n", " ")
            doc.append(f"| {label} | `{layers.get(key, 'UNKNOWN')}` | {detail} |")
        doc.append("\n")

        # ── 3. Verified Findings Matrix ────────────────────────────────────────
        doc.append("## 3. Verified Findings Matrix\n")
        if not verified_findings:
            doc.append("No machine-verified security vulnerabilities or defects found.\n")
        else:
            doc.append("| ID | Severity | Level | Title | Status |")
            doc.append("| :--- | :--- | :--- | :--- | :--- |")
            for f in verified_findings:
                sev = f.data.get("severity", "High")
                doc.append(f"| `{f.id}` | {sev} | `{f.level or 'L2_BUG_WITNESS'}` | {f.name} | {f.status} |")
            doc.append("\n")

        # ── 4. Detailed Findings (Proof-Carrying) ──────────────────────────────
        doc.append("## 4. Proof-Carrying Findings (Auditable Witnesses)\n")
        if not verified_findings:
            doc.append("No machine-verified findings or witnesses are available.\n")
        else:
            for idx, f in enumerate(verified_findings, 1):
                doc.append(f"### Finding #{idx}: {f.name}")
                doc.append(f"- ID: `{f.id}`")
                doc.append(f"- Severity: `{f.data.get('severity', 'High')}` | CVSS: `{f.data.get('cvss', 'N/A')}`")
                doc.append(f"- Status: `{f.status}`")
                doc.append(f"- Verification Level: `{f.level or 'L2_BUG_WITNESS'}`")
                doc.append(f"- Location: `{f.data.get('location', 'N/A')}`")
                doc.append(f"\n**Description & Root Cause**:\n{f.description}\n")

                if f.witness:
                    w = f.witness
                    doc.append("#### Machine Verification Witness")
                    doc.append(f"- Oracle: `{w.get('oracle', 'unknown')}`")
                    doc.append(f"- Exit Code: `{w.get('exit_code', 'N/A')}` ({w.get('duration_ms', 0):.1f}ms)")
                    doc.append(f"- Output SHA-256: `{w.get('output_hash', 'N/A')}`")
                    doc.append(f"- Reproducer Command:\n```bash\n{w.get('command', 'N/A')}\n```")
                    if w.get("signature"):
                        doc.append(f"- Oracle Signature:\n```text\n{w.get('signature')}\n```")
                    if w.get("reproducer_input"):
                        doc.append(f"- Input Witness Payload:\n```text\n{w.get('reproducer_input')}\n```")
                    for artifact_name, artifact_value in w.get("artifacts", {}).items():
                        if artifact_name.endswith("_sha256"):
                            doc.append(f"- `{artifact_name}`: `{artifact_value}`")
                        elif artifact_name == "python_wrapper":
                            doc.append(f"- Replayable Python verifier:\n```python\n{artifact_value}\n```")

                if f.status == STATUS_PATCHED and "patch_diff" in f.data:
                    doc.append("#### Verified Patch Remediation")
                    doc.append(f"```diff\n{f.data.get('patch_diff')}\n```")
                    if "reverify_log" in f.data:
                        doc.append(f"- Post-Patch Verification: `{f.data.get('reverify_log')}`")

                doc.append("\n---\n")

        # ── 5. Open Hypotheses ──────────────────────────────────────────────────
        doc.append("## 5. Open Hypotheses (Unverified)\n")
        if not open_hypotheses:
            doc.append("No open hypotheses.\n")
        else:
            doc.append("These are questions for investigation, not verified findings.\n")
            doc.append("| Hypothesis | Scope | Description |")
            doc.append("| :--- | :--- | :--- |")
            for hypothesis in open_hypotheses:
                name = hypothesis.name.replace("|", "\\|").replace("\n", " ")
                scope = hypothesis.scope.replace("|", "\\|").replace("\n", " ")
                description = hypothesis.description.replace("|", "\\|").replace("\n", " ")
                doc.append(f"| {name} | `{scope}` | {description} |")
            doc.append("\n")

        doc.append("## 6. Open Questions (Unresolved)\n")
        if not open_questions:
            doc.append("No open assessment questions.\n")
        else:
            for question in open_questions:
                text = question.description.replace("|", "\\|").replace("\n", " ")
                doc.append(f"- {text}\n")

        # ── 7. Inconclusive Memory ─────────────────────────────────────────────
        doc.append("## 7. Inconclusive Checks (Unresolved)\n")
        if not inconclusive_memory:
            doc.append("No inconclusive checks recorded.\n")
        else:
            doc.append("These checks did not establish either safety or a verified issue.\n")
            doc.append("| Check | Scope | Reason | Run |")
            doc.append("| :--- | :--- | :--- | :--- |")
            for item in inconclusive_memory:
                name = item.data.get("hypothesis", item.name).replace("|", "\\|").replace("\n", " ")
                reason = item.data.get("reason", item.description).replace("|", "\\|").replace("\n", " ")
                run_id = item.data.get("evidence", {}).get("run_id", "unknown")
                doc.append(f"| {name} | `{item.scope}` | {reason} | `{run_id}` |")
            doc.append("\n")

        # ── 8. Negative Memory ─────────────────────────────────────────────────
        doc.append("## 8. Negative Memory (Disproven & Safe Hypotheses)\n")
        doc.append("> *Negative memory records what did NOT work or was proven unreachable. This prevents future agent loops from thrashing over tested dead branches.*\n")
        if not negative_memory:
            doc.append("No negative paths recorded.")
        else:
            doc.append("| Hypothesis / Path | Oracle / Reason | Scope |")
            doc.append("| :--- | :--- | :--- |")
            for nm in negative_memory:
                reason = nm.data.get("reason", nm.description)
                doc.append(f"| `{nm.name}` | {reason} | `{nm.scope}` |")
            doc.append("\n") 

        # ── 9. Instructions ────────────────────────────────────────────────────
        doc.append("## 9. Remediation & Re-Verification Instructions\n")
        doc.append("Review each open finding before changing target code. The coding agent, not Vidhur, is responsible for proposing and applying fixes.\n")
        doc.append("After a fix, use Vidhur to rerun the finding's reproducer and the relevant project tests and checks, then update the finding status only when the evidence supports it.\n")

        content = "\n".join(doc)
        with open(self.output_path, "w", encoding="utf-8") as f:
            f.write(content)
        return content
