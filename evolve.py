"""
vidhur / evolve — turn verification into a fitness and hill-climb it (MAP-Elites).

This is the piece the architecture was missing: autonomous *discovery*, not just
verification of agent-supplied hypotheses.

Design:
- A candidate is an opaque bytes payload fed to a fixed harness command.
- An oracle runs the harness under the sealed verifier and grades the outcome on a
  small integer ladder (0..N). Grading is deterministic pattern matching — never an LLM.
- MAP-Elites keeps one elite per behavior-descriptor cell so the population stays
  diverse instead of collapsing to one local optimum.
"""
from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

from threat_graph import L2_BUG_WITNESS, L3_EXPLOITABLE, ThreatGraph
from verifier import SealedVerifier, VerificationWitness


@dataclass
class Candidate:
    payload: bytes
    parent_id: Optional[str] = None
    generation: int = 0

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.payload).hexdigest()


@dataclass
class FitnessResult:
    score: int
    descriptor: Tuple[str, ...]
    level: Optional[str] = None
    witness: Optional[Dict] = None
    reason: str = ""
    raw_output_hash: str = ""


class FitnessOracle:
    """Base class. Subclasses define how to run a harness and grade the outcome."""

    name: str = "base"
    max_score: int = 4

    def __init__(self, harness_cmd: str, verifier: SealedVerifier, cwd: str):
        self.harness_cmd = harness_cmd
        self.verifier = verifier
        self.cwd = cwd

    def descriptor(self, score: int, output: str, exit_code: int) -> Tuple[str, ...]:
        return (self._exit_class(exit_code), self._crash_class(output))

    def evaluate(self, candidate: Candidate) -> FitnessResult:
        raise NotImplementedError

    @staticmethod
    def _exit_class(exit_code: int) -> str:
        if exit_code == 0:
            return "clean"
        if exit_code < 0:
            return "signal"
        return f"exit_{exit_code // 32}xx" if exit_code >= 32 else f"exit_{exit_code}"

    @staticmethod
    def _crash_class(output: str) -> str:
        import re
        for label, pattern in (
            ("asan_heap_overflow", r"AddressSanitizer: heap-buffer-overflow"),
            ("asan_stack_overflow", r"AddressSanitizer: stack-buffer-overflow"),
            ("asan_use_after_free", r"AddressSanitizer: use-after-free"),
            ("ubsan", r"runtime error:"),
            ("segv", r"Segmentation fault"),
            ("abort", r"Aborted"),
        ):
            if re.search(pattern, output, re.IGNORECASE):
                return label
        return "none"


class SanitizerCrashOracle(FitnessOracle):
    """Ladder: 0 no effect | 1 non-zero exit | 2 sanitizer/signal | 3 leak marker | 4 RCE marker."""

    name = "sanitizer_crash"
    max_score = 4

    def __init__(
        self,
        harness_cmd: str,
        verifier: SealedVerifier,
        cwd: str,
        rce_marker: Optional[str] = None,
        leak_marker: Optional[str] = None,
    ):
        super().__init__(harness_cmd, verifier, cwd)
        self.rce_marker = rce_marker
        self.leak_marker = leak_marker

    def evaluate(self, candidate: Candidate) -> FitnessResult:
        code, stdout, stderr, dur = self.verifier.run_command(
            cmd=self.harness_cmd,
            cwd=self.cwd,
            input_data=candidate.payload.decode("latin-1"),
        )
        combined = f"{stdout}\n{stderr}"
        out_hash = self.verifier._hash_output(combined)

        score = 0
        reason = "no effect"
        level: Optional[str] = None
        witness: Optional[Dict] = None

        if self.rce_marker and self.rce_marker in combined:
            score, reason, level = 4, "RCE marker present in output", L3_EXPLOITABLE
        elif self.leak_marker and self.leak_marker in combined:
            score, reason = 3, "leak marker present in output"
        elif code < 0 and abs(code) in (11, 6, 8, 4):
            score, reason, level = 2, f"signal exit {code}", L2_BUG_WITNESS
        elif "AddressSanitizer" in combined or "runtime error:" in combined:
            score, reason, level = 2, "sanitizer signature", L2_BUG_WITNESS
        elif code != 0:
            score, reason = 1, f"non-zero exit {code}"

        if level:
            witness = VerificationWitness(
                oracle=self.name,
                command=self.harness_cmd,
                exit_code=code,
                duration_ms=dur,
                output_hash=out_hash,
                signature=reason,
                reproducer_input=candidate.payload.decode("latin-1")[:512],
                layer="evolve",
                artifacts={"candidate_sha256": candidate.sha256},
            ).to_dict()

        return FitnessResult(
            score=score,
            descriptor=self.descriptor(score, combined, code),
            level=level,
            witness=witness,
            reason=reason,
            raw_output_hash=out_hash,
        )


@dataclass
class Elite:
    candidate: Candidate
    fitness: FitnessResult
    found_at: float = field(default_factory=__import__("time").time)


class MapElites:
    def __init__(self, max_cells: int = 256):
        self.elites: Dict[Tuple[str, ...], Elite] = {}
        self.max_cells = max_cells
        self.evaluations = 0
        self.improvements = 0

    def offer(self, candidate: Candidate, fitness: FitnessResult) -> bool:
        self.evaluations += 1
        key = fitness.descriptor
        current = self.elites.get(key)
        if current is None or fitness.score > current.fitness.score:
            self.elites[key] = Elite(candidate=candidate, fitness=fitness)
            self.improvements += 1
            return True
        return False

    def best(self) -> Optional[Elite]:
        if not self.elites:
            return None
        return max(self.elites.values(), key=lambda e: e.fitness.score)

    def sample_parent(self, rng: random.Random) -> Candidate:
        elites = list(self.elites.values())
        if not elites:
            raise RuntimeError("No elites to sample from")
        elites.sort(key=lambda e: e.fitness.score, reverse=True)
        top = elites[: max(1, len(elites) // 2)]
        return rng.choice(top).candidate


def mutate(candidate: Candidate, rng: random.Random, max_len: int = 65536) -> Candidate:
    payload = bytearray(candidate.payload) or bytearray(b"\x00" * 16)
    for _ in range(rng.randint(1, 4)):
        choice = rng.random()
        if choice < 0.4 and payload:
            payload[rng.randrange(len(payload))] ^= 1 << rng.randrange(8)
        elif choice < 0.6 and payload:
            payload[rng.randrange(len(payload))] = rng.randrange(256)
        elif choice < 0.75 and len(payload) < max_len:
            i = rng.randrange(len(payload) + 1)
            payload[i:i] = bytes(rng.randrange(256) for _ in range(rng.randint(1, 8)))
        elif choice < 0.9 and payload:
            i = rng.randrange(len(payload))
            j = min(len(payload), i + rng.randint(1, 8))
            del payload[i:j]
        else:
            pattern = bytes(rng.randrange(256) for _ in range(rng.randint(2, 16)))
            i = rng.randrange(len(payload) + 1)
            payload[i:i] = pattern
    return Candidate(payload=bytes(payload[:max_len]), parent_id=candidate.sha256,
                     generation=candidate.generation + 1)


@dataclass
class EvolveConfig:
    generations: int = 100
    batch_size: int = 32
    seed_payload: bytes = b""
    max_len: int = 65536
    rng_seed: int = 0


@dataclass
class EvolveReport:
    generations: int
    evaluations: int
    improvements: int
    best_score: int
    best_descriptor: Tuple[str, ...]
    elite_count: int
    verified_witnesses: int


def evolve(
    oracle: FitnessOracle,
    graph: ThreatGraph,
    config: EvolveConfig,
    scope: str = "evolve",
    on_improvement: Optional[Callable[[Candidate, FitnessResult], None]] = None,
) -> EvolveReport:
    rng = random.Random(config.rng_seed)
    pool = MapElites()
    seed = Candidate(payload=config.seed_payload or b"\x00" * 16)
    pool.offer(seed, oracle.evaluate(seed))

    verified_witnesses = 0
    for _ in range(config.generations):
        batch: List[Candidate] = []
        for _ in range(config.batch_size):
            try:
                parent = pool.sample_parent(rng)
            except RuntimeError:
                parent = seed
            batch.append(mutate(parent, rng, max_len=config.max_len))

        for candidate in batch:
            result = oracle.evaluate(candidate)
            improved = pool.offer(candidate, result)
            if improved and result.level and result.witness:
                graph.record_finding(
                    name=f"Evolved primitive {candidate.sha256[:8]}",
                    description=result.reason,
                    level=result.level,
                    witness=result.witness,
                    scope=f"{scope}:{candidate.sha256[:8]}",
                    data={"fitness_score": result.score, "descriptor": list(result.descriptor)},
                )
                verified_witnesses += 1
            if improved and on_improvement:
                on_improvement(candidate, result)

    best = pool.best()
    graph.save()
    return EvolveReport(
        generations=config.generations,
        evaluations=pool.evaluations,
        improvements=pool.improvements,
        best_score=best.fitness.score if best else 0,
        best_descriptor=best.fitness.descriptor if best else (),
        elite_count=len(pool.elites),
        verified_witnesses=verified_witnesses,
    )