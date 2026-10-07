"""
vidhur / threat_graph — the subconscious threat, state, and negative memory graph (v2).

v2 changes:
- Untrusted propagation: nodes created with `derived_from` inherit `untrusted`.
- `declassify()` clears untrusted only with structured, oracle-backed evidence.
- `get_open_hypotheses` ranks by computed *activation*, not creation time.
- `decay_edges` fades stale associations.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

ASSET = "asset"
BOUNDARY = "boundary"
INPUT_SOURCE = "input_source"
SINK = "sink"
HYPOTHESIS = "hypothesis"
PRIMITIVE = "primitive"
DISPROOF = "disproof"
INCONCLUSIVE = "inconclusive"
QUESTION = "question"
FINDING = "finding"

STATUS_OPEN = "OPEN"
STATUS_VERIFIED = "VERIFIED"
STATUS_DISPROVEN = "DISPROVEN"
STATUS_UNKNOWN = "UNKNOWN"
STATUS_FAILED = "FAILED"
STATUS_NOT_APPLICABLE = "NOT_APPLICABLE"
STATUS_RESOLVED = "RESOLVED"
STATUS_PATCHED = "PATCHED"

L0_HYPOTHESIS = "L0_HYPOTHESIS"
L1_REACHABLE = "L1_REACHABLE"
L2_BUG_WITNESS = "L2_BUG_WITNESS"
L3_EXPLOITABLE = "L3_EXPLOITABLE"
L4_CHAIN = "L4_CHAIN"


class UntrustedNodeError(PermissionError):
    """Raised when an action would operate on an untrusted node without declassification."""


@dataclass
class Node:
    id: str
    kind: str
    name: str
    description: str = ""
    status: str = STATUS_OPEN
    level: Optional[str] = None
    confidence: float = 1.0
    untrusted: bool = False
    data: Dict[str, Any] = field(default_factory=dict)
    witness: Optional[Dict[str, Any]] = None
    scope: str = "global"
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    declassified_at: Optional[float] = None


@dataclass
class Edge:
    src: str
    dst: str
    kind: str = "relates_to"
    weight: float = 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)
    updated_at: float = field(default_factory=time.time)


class ThreatGraph:
    def __init__(self, storage_dir: Optional[pathlib.Path] = None):
        self.storage_dir = pathlib.Path(storage_dir) if storage_dir else pathlib.Path.home() / ".cache" / "vidhur" / "graph"
        self.nodes: Dict[str, Node] = {}
        self.edges: Dict[Tuple[str, str, str], Edge] = {}
        self.load()

    def _hash_id(self, prefix: str, key: str) -> str:
        h = hashlib.sha256(key.strip().lower().encode("utf-8")).hexdigest()[:12]
        return f"{prefix}_{h}"

    # ── Nodes ─────────────────────────────────────────────────────────────────

    def add_node(
        self,
        kind: str,
        name: str,
        description: str = "",
        status: str = STATUS_OPEN,
        level: Optional[str] = None,
        untrusted: bool = False,
        data: Optional[Dict[str, Any]] = None,
        witness: Optional[Dict[str, Any]] = None,
        scope: str = "global",
        node_id: Optional[str] = None,
        derived_from: Optional[Iterable[str]] = None,
    ) -> Node:
        nid = node_id or self._hash_id(kind, f"{scope}:{name}")
        derived_from = list(derived_from or [])
        inherited_untrusted = any(
            (src_node := self.nodes.get(src)) is not None and src_node.untrusted
            for src in derived_from
        )
        if nid in self.nodes:
            node = self.nodes[nid]
            node.description = description or node.description
            node.status = status if status != STATUS_OPEN else node.status
            node.level = level or node.level
            if data:
                node.data.update(data)
            if witness:
                node.witness = witness
            if inherited_untrusted:
                node.untrusted = True
            node.updated_at = time.time()
            for src in derived_from:
                if src in self.nodes:
                    self.add_edge(src, nid, kind="derives")
            return node

        node = Node(
            id=nid, kind=kind, name=name, description=description,
            status=status, level=level,
            untrusted=untrusted or inherited_untrusted,
            data=data or {}, witness=witness, scope=scope,
        )
        self.nodes[nid] = node
        for src in derived_from:
            if src in self.nodes:
                self.add_edge(src, nid, kind="derives")
        return node

    def add_hypothesis(
        self,
        name: str,
        description: str,
        target_sink: Optional[str] = None,
        scope: str = "global",
        derived_from: Optional[Iterable[str]] = None,
    ) -> Node:
        node = self.add_node(
            kind=HYPOTHESIS, name=name, description=description,
            status=STATUS_OPEN, level=L0_HYPOTHESIS, scope=scope,
            derived_from=derived_from,
        )
        if target_sink:
            sink_node = self.add_node(kind=SINK, name=target_sink, scope=scope)
            self.add_edge(node.id, sink_node.id, kind="targets")
        return node

    def declassify(self, node_id: str, evidence: Dict[str, Any]) -> Node:
        """Clear untrusted only with structured, oracle-backed evidence."""
        if not isinstance(evidence, dict) or not evidence.get("oracle") or "result" not in evidence:
            raise ValueError("Declassification requires structured evidence with an oracle and result")
        node = self.nodes.get(node_id)
        if node is None:
            raise KeyError(f"Unknown node: {node_id}")
        node.untrusted = False
        node.declassified_at = time.time()
        node.data.setdefault("declassification_history", []).append(evidence)
        node.updated_at = time.time()
        return node

    def require_trusted(self, node_id: str) -> Node:
        node = self.nodes.get(node_id)
        if node is None:
            raise KeyError(f"Unknown node: {node_id}")
        if node.untrusted:
            raise UntrustedNodeError(
                f"Node {node_id} ({node.name!r}) is untrusted; declassify with independent evidence first"
            )
        return node

    def record_disproof(self, hypothesis_name_or_id, reason, scope="global", evidence=None) -> Node:
        if not isinstance(evidence, dict) or not evidence.get("oracle") or "result" not in evidence:
            raise ValueError("Disproof requires structured evidence with an oracle and result")
        hyp_node = self.nodes.get(hypothesis_name_or_id) or self.nodes.get(
            self._hash_id(HYPOTHESIS, f"{scope}:{hypothesis_name_or_id}")
        )
        if hyp_node:
            hyp_node.status = STATUS_DISPROVEN
        disproof = self.add_node(
            kind=DISPROOF, name=f"Disproved: {hypothesis_name_or_id}",
            description=reason, status=STATUS_DISPROVEN,
            data={"reason": reason, "evidence": evidence, "hypothesis": hypothesis_name_or_id},
            scope=scope,
        )
        if hyp_node:
            self.add_edge(disproof.id, hyp_node.id, kind="contradicts")
        return disproof

    def record_inconclusive(self, hypothesis_name_or_id, reason, scope="global", evidence=None) -> Node:
        node = self.add_node(
            kind=INCONCLUSIVE, name=f"Inconclusive: {hypothesis_name_or_id}",
            description=reason, status=STATUS_UNKNOWN,
            data={"reason": reason, "evidence": evidence or {}, "hypothesis": hypothesis_name_or_id},
            scope=scope,
        )
        hyp_id = self._hash_id(HYPOTHESIS, f"{scope}:{hypothesis_name_or_id}")
        hyp = self.nodes.get(hyp_id)
        if hyp:
            self.add_edge(node.id, hyp.id, kind="inconclusive_for")
        return node

    def add_question(self, question, scope="global", about=None, untrusted=False, provenance=None) -> Node:
        node = self.add_node(
            kind=QUESTION, name=question, description=question,
            status=STATUS_OPEN, level=L0_HYPOTHESIS, scope=scope,
            untrusted=untrusted, data={"resolved": False, "provenance": provenance or {}},
        )
        if about and about in self.nodes:
            self.add_edge(node.id, about, kind="asks_about")
        return node

    def resolve_question(self, question_id, answer, evidence) -> Node:
        if not isinstance(evidence, dict) or not evidence.get("oracle") or "result" not in evidence:
            raise ValueError("Question resolution requires structured evidence with an oracle and result")
        node = self.nodes.get(question_id)
        if node is None or node.kind != QUESTION:
            raise KeyError(f"Unknown question: {question_id}")
        node.status = STATUS_RESOLVED
        node.data.update({"resolved": True, "answer": answer, "resolution_evidence": evidence})
        node.updated_at = time.time()
        return node

    def record_finding(self, name, description, level, witness, scope="global", data=None) -> Node:
        return self.add_node(
            kind=FINDING, name=name, description=description,
            status=STATUS_VERIFIED, level=level, witness=witness, scope=scope, data=data or {},
        )

    # ── Edges ─────────────────────────────────────────────────────────────────

    def add_edge(self, src, dst, kind="relates_to", weight=1.0, metadata=None) -> Edge:
        key = (src, dst, kind)
        if key in self.edges:
            edge = self.edges[key]
            edge.weight = min(10.0, edge.weight + 0.5)
            edge.updated_at = time.time()
            if metadata:
                edge.metadata.update(metadata)
            return edge
        edge = Edge(src=src, dst=dst, kind=kind, weight=weight, metadata=metadata or {})
        self.edges[key] = edge
        return edge

    def decay_edges(self, half_life_days: float = 30.0, floor: float = 0.05) -> int:
        """Exponential decay on edge weights based on last reinforcement."""
        now = time.time()
        half_life_s = max(1.0, half_life_days * 86400.0)
        decayed = 0
        for edge in self.edges.values():
            age_s = now - edge.updated_at
            if age_s <= 0:
                continue
            factor = 0.5 ** (age_s / half_life_s)
            new_weight = edge.weight * factor
            if new_weight < floor <= edge.weight:
                decayed += 1
            edge.weight = max(floor, new_weight)
        return decayed

    # ── Activation & queries ──────────────────────────────────────────────────

    def _in_scope(self, node, scope, scope_prefix) -> bool:
        return (scope is None or node.scope == scope) and (scope_prefix is None or node.scope.startswith(scope_prefix))

    def _activation(self, node: Node, now: Optional[float] = None) -> float:
        now = now or time.time()
        age_days = max(0.0, (now - node.updated_at) / 86400.0)
        recency = 1.0 / (1.0 + age_days)
        incoming = sum(
            edge.weight for edge in self.edges.values()
            if edge.dst == node.id
            and edge.src in self.nodes
            and self.nodes[edge.src].status != STATUS_DISPROVEN
        )
        scope_bonus = 0.1 if node.scope != "global" else 0.0
        return (incoming + node.confidence + scope_bonus) * recency

    def get_open_hypotheses(self, scope=None, scope_prefix=None) -> List[Node]:
        candidates = [
            n for n in self.nodes.values()
            if n.kind == HYPOTHESIS and n.status == STATUS_OPEN and self._in_scope(n, scope, scope_prefix)
        ]
        return sorted(candidates, key=lambda n: self._activation(n), reverse=True)

    def get_verified_findings(self, scope=None, scope_prefix=None) -> List[Node]:
        return sorted(
            (
                n for n in self.nodes.values()
                if n.kind in (FINDING, PRIMITIVE)
                and n.status in (STATUS_VERIFIED, STATUS_PATCHED)
                and self._in_scope(n, scope, scope_prefix)
            ),
            key=lambda n: n.created_at,
        )

    def get_negative_memory(self, scope=None, scope_prefix=None) -> List[Node]:
        return sorted(
            (n for n in self.nodes.values() if n.kind == DISPROOF and self._in_scope(n, scope, scope_prefix)),
            key=lambda n: n.created_at,
        )

    def get_inconclusive_memory(self, scope=None, scope_prefix=None) -> List[Node]:
        return sorted(
            (n for n in self.nodes.values() if n.kind == INCONCLUSIVE and self._in_scope(n, scope, scope_prefix)),
            key=lambda n: n.created_at,
        )

    def get_open_questions(self, scope=None, scope_prefix=None) -> List[Node]:
        return sorted(
            (
                n for n in self.nodes.values()
                if n.kind == QUESTION and not n.data.get("resolved", False)
                and self._in_scope(n, scope, scope_prefix)
            ),
            key=lambda n: n.created_at,
        )

    def is_disproven(self, name_or_concept: str, scope: str = "global") -> bool:
        nid = self._hash_id(HYPOTHESIS, f"{scope}:{name_or_concept}")
        if nid in self.nodes and self.nodes[nid].status == STATUS_DISPROVEN:
            return True
        for n in self.nodes.values():
            if (
                n.kind == DISPROOF and n.scope == scope
                and n.data.get("hypothesis", "").strip().lower() == name_or_concept.strip().lower()
            ):
                return True
        return False

    # ── Persistence ───────────────────────────────────────────────────────────

    def save(self) -> None:
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        dump = {
            "version": "2.0",
            "timestamp": time.time(),
            "nodes": {nid: asdict(node) for nid, node in self.nodes.items()},
            "edges": [asdict(edge) for edge in self.edges.values()],
        }
        with open(self.storage_dir / "threat_graph.json", "w", encoding="utf-8") as f:
            json.dump(dump, f, indent=2)

    def load(self) -> None:
        path = self.storage_dir / "threat_graph.json"
        if not path.exists():
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                dump = json.load(f)
            self.nodes = {nid: Node(**data) for nid, data in dump.get("nodes", {}).items()}
            self.edges = {(e["src"], e["dst"], e["kind"]): Edge(**e) for e in dump.get("edges", [])}
        except Exception:
            self.nodes = {}
            self.edges = {} 