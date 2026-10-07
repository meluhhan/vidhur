"""Machine-validated rules of engagement for a Vidhur assessment (v2)."""
from __future__ import annotations

import hashlib
import json
import pathlib
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


class PolicyError(ValueError):
    """Raised when the engagement policy is missing or invalid."""


@dataclass(frozen=True)
class AdversarialOracle:
    name: str
    rejection_pattern: str
    description: str = ""

    def compiled(self) -> re.Pattern:
        try:
            return re.compile(self.rejection_pattern, re.IGNORECASE)
        except re.error as error:
            raise PolicyError(f"Invalid rejection_pattern in oracle {self.name}: {error}") from error


@dataclass(frozen=True)
class EngagementPolicy:
    path: pathlib.Path
    target: Optional[pathlib.Path]
    revision: str
    goal: str
    crown_jewels: List[str]
    forbidden_actions: List[str]
    authorized: bool
    in_scope: List[str]
    out_of_scope: List[str]
    allow_host_execution: bool
    allow_package_installation: bool
    adversarial_oracles: List[AdversarialOracle]
    max_commands: int
    command_timeout_seconds: int
    total_runtime_seconds: int
    fingerprint: str

    def execution_block_reason(self, target_dir: pathlib.Path, cli_opt_in: bool) -> Optional[str]:
        if not self.authorized:
            return "Rules of engagement do not authorize testing"
        if self.target is None:
            return "Rules of engagement do not name an authorized target"
        if pathlib.Path(target_dir).resolve() != self.target:
            return f"Target does not match authorized path: {self.target}"
        if not self.allow_host_execution:
            return "Rules of engagement do not permit host command execution"
        if not cli_opt_in:
            return "Pass --allow-host-execution to confirm host command execution"
        return None

    def find_adversarial_oracle(self, name: str) -> Optional[AdversarialOracle]:
        for oracle in self.adversarial_oracles:
            if oracle.name == name:
                return oracle
        return None

    def allows_path(self, target_dir: pathlib.Path, candidate: pathlib.Path) -> bool:
        target_dir = pathlib.Path(target_dir).resolve()
        candidate = pathlib.Path(candidate).resolve()
        try:
            relative = candidate.relative_to(target_dir).as_posix()
        except ValueError:
            return False
        if any(_matches(relative, pattern) for pattern in self.out_of_scope):
            return False
        return any(_matches(relative, pattern) for pattern in self.in_scope)


_GLOB_CACHE: Dict[str, re.Pattern] = {}


def _matches(relative_path: str, pattern: str) -> bool:
    """Single canonical matcher. Gitignore-style: `**` crosses segments, `*` does not."""
    normalized = pattern.strip()
    if normalized.startswith("./"):
        normalized = normalized[2:]
    if not normalized or normalized in (".", "**"):
        return True
    compiled = _GLOB_CACHE.get(normalized)
    if compiled is None:
        compiled = _compile_glob(normalized)
        _GLOB_CACHE[normalized] = compiled
    return bool(compiled.match(relative_path))


def _compile_glob(pattern: str) -> re.Pattern:
    parts = []
    i = 0
    while i < len(pattern):
        c = pattern[i]
        if c == "*":
            if i + 1 < len(pattern) and pattern[i + 1] == "*":
                if i + 2 < len(pattern) and pattern[i + 2] == "/":
                    parts.append("(?:.*/)?")
                    i += 3
                else:
                    parts.append(".*")
                    i += 2
            else:
                parts.append("[^/]*")
                i += 1
        elif c == "?":
            parts.append("[^/]")
            i += 1
        else:
            parts.append(re.escape(c))
            i += 1
    return re.compile("^" + "".join(parts) + "$")


def load_policy(policy_path: Optional[str | pathlib.Path] = None) -> EngagementPolicy:
    path = pathlib.Path(policy_path) if policy_path else pathlib.Path(__file__).with_name("input.md")
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as error:
        raise PolicyError(f"Could not read policy file {path}: {error}") from error

    blocks = re.findall(r"```json\s*(.*?)```", text, flags=re.DOTALL | re.IGNORECASE)
    if len(blocks) != 1:
        raise PolicyError("input.md must contain exactly one fenced JSON rules-of-engagement block")
    try:
        raw: Dict[str, Any] = json.loads(blocks[0])
    except json.JSONDecodeError as error:
        raise PolicyError(f"Invalid rules-of-engagement JSON: {error}") from error
    if not isinstance(raw, dict) or raw.get("version") not in (1, 2):
        raise PolicyError("Policy must be a JSON object with version 1 or 2")

    target_value = raw.get("target")
    if target_value is not None and not isinstance(target_value, str):
        raise PolicyError("Policy target must be a path string or empty")
    target = None
    if target_value and target_value.strip():
        target_path = pathlib.Path(target_value).expanduser()
        target = (path.parent / target_path).resolve() if not target_path.is_absolute() else target_path.resolve()

    authorization = raw.get("authorization", {})
    scope = raw.get("scope", {})
    execution = raw.get("execution", {})
    budget = raw.get("budget", {})
    if not all(isinstance(value, dict) for value in (authorization, scope, execution, budget)):
        raise PolicyError("authorization, scope, execution, and budget must be JSON objects")

    in_scope = _string_list(scope.get("in_scope", []), "scope.in_scope")
    out_of_scope = _string_list(scope.get("out_of_scope", []), "scope.out_of_scope")
    crown_jewels = _string_list(raw.get("crown_jewels", []), "crown_jewels")
    forbidden_actions = _string_list(raw.get("forbidden_actions", []), "forbidden_actions")
    goal = raw.get("goal", "")
    if not isinstance(goal, str):
        raise PolicyError("goal must be a string")
    if authorization.get("authorized", False) and not in_scope:
        raise PolicyError("An authorized engagement must declare at least one in-scope path")

    max_commands = _bounded_int(budget.get("max_commands", 0), "budget.max_commands", 0, 1000)
    timeout_s = _bounded_int(budget.get("command_timeout_seconds", 60), "budget.command_timeout_seconds", 1, 3600)
    total_s = _bounded_int(budget.get("total_runtime_seconds", 0), "budget.total_runtime_seconds", 0, 86400)
    allow_execution = execution.get("allow_host_execution", False)
    allow_packages = execution.get("allow_package_installation", False)
    authorized = authorization.get("authorized", False)
    if not all(isinstance(v, bool) for v in (allow_execution, allow_packages, authorized)):
        raise PolicyError("authorization.authorized, execution.allow_host_execution, execution.allow_package_installation must be booleans")
    revision = raw.get("revision", "unspecified")
    if not isinstance(revision, str) or not revision.strip():
        raise PolicyError("revision must be a non-empty commit, release, or source snapshot identifier")
    if authorized and revision.strip().lower() in {"unspecified", "unknown", "latest"}:
        raise PolicyError("Authorized assessments must pin revision to a commit, release, or source snapshot")
    if allow_execution and (not authorized or target is None or max_commands == 0 or total_s == 0):
        raise PolicyError("Host execution requires authorization, a target, and nonzero command/time budgets")
    if allow_packages and not allow_execution:
        raise PolicyError("Package installation requires host execution to be authorized")
    if authorized and (target is None or not target.is_dir()):
        raise PolicyError("Authorized policy target must resolve to an existing directory")

    adversarial_oracles: List[AdversarialOracle] = []
    raw_oracles = raw.get("adversarial_oracles", [])
    if not isinstance(raw_oracles, list):
        raise PolicyError("adversarial_oracles must be a list")
    seen_names = set()
    for entry in raw_oracles:
        if not isinstance(entry, dict):
            raise PolicyError("Each adversarial_oracles entry must be an object")
        name = entry.get("name")
        pattern = entry.get("rejection_pattern")
        if not isinstance(name, str) or not name.strip():
            raise PolicyError("Each adversarial_oracle needs a non-empty name")
        if not isinstance(pattern, str) or not pattern.strip():
            raise PolicyError(f"Adversarial oracle {name} needs a non-empty rejection_pattern")
        if name in seen_names:
            raise PolicyError(f"Duplicate adversarial_oracle name: {name}")
        seen_names.add(name)
        oracle = AdversarialOracle(
            name=name.strip(),
            rejection_pattern=pattern,
            description=str(entry.get("description", "")),
        )
        oracle.compiled()
        adversarial_oracles.append(oracle)

    canonical = json.dumps(raw, sort_keys=True, separators=(",", ":"))
    return EngagementPolicy(
        path=path.resolve(),
        target=target,
        revision=revision.strip(),
        goal=goal.strip(),
        crown_jewels=crown_jewels,
        forbidden_actions=forbidden_actions,
        authorized=authorized,
        in_scope=in_scope,
        out_of_scope=out_of_scope,
        allow_host_execution=allow_execution,
        allow_package_installation=allow_packages,
        adversarial_oracles=adversarial_oracles,
        max_commands=max_commands,
        command_timeout_seconds=timeout_s,
        total_runtime_seconds=total_s,
        fingerprint=hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
    ) 


def _string_list(value: Any, field_name: str) -> List[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) or not item.strip() for item in value):
        raise PolicyError(f"{field_name} must be a list of non-empty strings")
    return value


def _bounded_int(value: Any, field_name: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise PolicyError(f"{field_name} must be an integer from {minimum} through {maximum}")
    return value 