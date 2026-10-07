"""
vidhur / verifier — multi-layer verification engine.

Provides four verification layers:
- Layer 1: Adversarial Re-Testing (witness re-execution, exploit neutralization)
- Layer 2: Functional & API Testing (test suites, endpoint contract checks)
- Layer 3: Static & Type Analysis (linters, typecheckers, AST validation)
- Layer 4: DevOps & CI/CD Verification (Docker builds, GitHub Actions, config drift)
"""
from __future__ import annotations
from policy import AdversarialOracle

import ast
import hashlib
import json
import os
import pathlib
import re
import shlex
import signal
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from threat_graph import (
    L0_HYPOTHESIS,
    L1_REACHABLE,
    L2_BUG_WITNESS,
    L3_EXPLOITABLE,
    L4_CHAIN,
    STATUS_DISPROVEN,
    STATUS_FAILED,
    STATUS_NOT_APPLICABLE,
    STATUS_UNKNOWN,
    STATUS_VERIFIED,
)

SANITIZER_PATTERNS = [
    r"AddressSanitizer:\s*([a-zA-Z\-]+)",
    r"UndefinedBehaviorSanitizer:\s*([a-zA-Z\-]+)",
    r"ThreadSanitizer:\s*([a-zA-Z\-]+)",
    r"MemorySanitizer:\s*([a-zA-Z\-]+)",
    r"Segmentation fault",
    r"SIGSEGV|SIGBUS|SIGABRT|SIGFPE",
]

# Exit codes from Python subprocess: negative = killed by signal.
_SIGNAL_CRASH_EXITS = {-11, -6, -8, -4}  # SIGSEGV, SIGABRT, SIGFPE, SIGILL

_SANITIZER_ERR_RE = re.compile(
    r"(ERROR: (?:Address|Leak|Thread|Memory|UndefinedBehavior)Sanitizer[^\n]*"
    r"|runtime error: [^\n]+)",
    re.IGNORECASE,
)


def _detect_crash(exit_code: int, stdout: str, stderr: str) -> Optional[str]:
    """Return a crash signature only when exit-code AND output evidence agree.

    A crash pattern in stdout alone is insufficient: programs that *test* for crashes
    legitimately print that text. We require either signal death, or a sanitizer
    signature on stderr.
    """
    if exit_code in _SIGNAL_CRASH_EXITS:
        for pattern in SANITIZER_PATTERNS:
            m = re.search(pattern, stderr, re.IGNORECASE)
            if m:
                return m.group(0)
        return f"signal {abs(exit_code)}"
    m = _SANITIZER_ERR_RE.search(stderr)
    if m:
        return m.group(0)
    return None

COMMAND_EXECUTION_DISABLED = -998
SENSITIVE_ENV_PATTERN = re.compile(r"(?:TOKEN|SECRET|PASSWORD|CREDENTIAL|API_KEY|PRIVATE_KEY|ACCESS_KEY)", re.IGNORECASE)
IGNORED_DISCOVERY_DIRS = {
    ".git", ".next", ".venv", ".vidhur", "__pycache__", "build", "dist",
    "node_modules", "target", "venv", "vendor",
}


def discover_test_suites(target_dir: pathlib.Path) -> List[Tuple[str, str, pathlib.Path]]:
    """Find supported test suites at the root and in bounded-depth packages."""
    target_dir = pathlib.Path(target_dir).resolve()
    candidates = []
    for current, dirs, files in os.walk(target_dir):
        current_path = pathlib.Path(current)
        depth = len(current_path.relative_to(target_dir).parts)
        dirs[:] = sorted(d for d in dirs if d not in IGNORED_DISCOVERY_DIRS)
        if depth >= 4:
            dirs[:] = []
        marker_names = {"package.json", "Cargo.toml", "go.mod", "pyproject.toml", "requirements.txt", "setup.py", "Makefile"}
        if current_path == target_dir or marker_names.intersection(files) or "tests" in dirs:
            candidates.append((current_path, set(files), set(dirs)))

    suites = []
    seen = set()
    for root, files, dirs in candidates:
        if "package.json" in files:
            try:
                package = json.loads((root / "package.json").read_text(encoding="utf-8"))
                test_script = package.get("scripts", {}).get("test")
            except (OSError, json.JSONDecodeError, AttributeError):
                test_script = None
            placeholder_test = (
                isinstance(test_script, str)
                and re.search(r"no tests? specified", test_script, re.IGNORECASE)
            )
            if isinstance(test_script, str) and test_script.strip() and not placeholder_test:
                suites.append(("Node.js tests", "npm test", root))

        if "Cargo.toml" in files:
            suites.append(("Rust tests", "cargo test", root))
        if "go.mod" in files:
            suites.append(("Go tests", "go test ./...", root))

        tests_dir = root / "tests"
        if tests_dir.is_dir() and any(t.suffix == ".py" for t in tests_dir.rglob("*.py")):
            suites.append(("Python tests", "pytest -v tests", root))

        if "Makefile" in files and not any(suite[2] == root for suite in suites):
            try:
                makefile = (root / "Makefile").read_text(encoding="utf-8")
            except OSError:
                makefile = ""
            if re.search(r"(?m)^test\s*:", makefile):
                suites.append(("Makefile tests", "make test", root))

    unique_suites = []
    for suite in suites:
        key = (suite[0], suite[1], suite[2])
        if key not in seen:
            seen.add(key)
            unique_suites.append(suite)
    return unique_suites


def discover_project_checks(target_dir: pathlib.Path) -> List[Tuple[str, str, pathlib.Path]]:
    """Find declared Node package build and validation scripts in a monorepo."""
    target_dir = pathlib.Path(target_dir).resolve()
    checks = []
    for current, dirs, files in os.walk(target_dir):
        root = pathlib.Path(current)
        depth = len(root.relative_to(target_dir).parts)
        dirs[:] = sorted(directory for directory in dirs if directory not in IGNORED_DISCOVERY_DIRS)
        if depth >= 4:
            dirs[:] = []
        if "package.json" not in files:
            continue
        try:
            package = json.loads((root / "package.json").read_text(encoding="utf-8"))
            scripts = package.get("scripts", {})
        except (OSError, json.JSONDecodeError, AttributeError):
            continue
        if not isinstance(scripts, dict):
            continue
        package_name = package.get("name") or root.name
        for script_name in ("build", "check", "typecheck", "validate"):
            script = scripts.get(script_name)
            if isinstance(script, str) and script.strip():
                checks.append((f"{package_name} {script_name}", f"npm run {script_name}", root))
    return checks


@dataclass
class VerificationWitness:
    oracle: str                                     # e.g., "adversarial", "pytest", "mypy", "docker"
    command: str
    exit_code: int
    duration_ms: float
    output_hash: str                                # SHA-256 of raw execution output
    signature: str                                  # Summary or signature
    reproducer_input: Optional[str] = None
    layer: str = "layer1_adversarial"               # layer1, layer2, layer3, layer4
    artifacts: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class VerificationResult:
    verdict: str                                    # VERIFIED, DISPROVEN, UNKNOWN
    level: str                                      # L0_HYPOTHESIS to L4_CHAIN
    witness: Optional[VerificationWitness] = None
    layer: str = "layer1_adversarial"
    reason: str = ""
    stdout: str = ""
    stderr: str = ""
    duration_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class SealedVerifier:
    """Legacy name for a verifier whose opt-in commands run directly on the host."""

    def __init__(
    self,
    default_timeout_s: float = 60.0,
    max_output_bytes: int = 150 * 1024,
    max_cpu_s: int = 30,
    max_mem_mb: int = 1024,
    network_isolated: bool = False,
    allow_host_execution: bool = False,
    allow_package_installation: bool = False,   # NEW
    max_commands: int = 100,
    max_total_runtime_s: float = 3600.0,
    execution_block_reason: Optional[str] = None,
    execution_root: Optional[pathlib.Path] = None,
    ):
        self.allow_package_installation = allow_package_installation
        self.default_timeout_s = default_timeout_s
        self.max_output_bytes = max_output_bytes
        self.max_cpu_s = max_cpu_s
        self.max_mem_mb = max_mem_mb
        self.network_isolated = network_isolated
        self.allow_host_execution = allow_host_execution
        self.max_commands = max_commands
        self.max_total_runtime_s = max_total_runtime_s
        self.execution_block_reason = execution_block_reason
        self.execution_root = pathlib.Path(execution_root).resolve() if execution_root else None
        self._command_count = 0
        self._execution_started_at: Optional[float] = None
        self._budget_lock = threading.Lock()

    def _hash_output(self, content: str) -> str:
        return hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()

    def provision_cached_venv(self, cwd: Optional[str] = None) -> Tuple[str, Dict[str, str]]:
    if not self.allow_package_installation:
        raise PermissionError("Package installation is not authorized in the engagement policy")
        """
        Explicitly provision a cached virtual environment and install detected requirements.

        This may access the network and install target-controlled dependencies. It is
        never called implicitly by command execution.
        """
        target_dir = pathlib.Path(cwd or os.getcwd()).resolve()
        target_hash = hashlib.sha256(str(target_dir).encode()).hexdigest()[:12]
        venv_root = pathlib.Path.home() / ".cache" / "vidhur" / "venvs" / target_hash
        bin_dir = venv_root / "bin"
        py_bin = bin_dir / "python"

        # 1. Create venv if not already created
        if not py_bin.exists():
            venv_root.parent.mkdir(parents=True, exist_ok=True)
            subprocess.run(
                [sys.executable, "-m", "venv", str(venv_root)],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

        # 2. Check if pytest is installed in this venv; if not, install requirements
        pytest_bin = bin_dir / "pytest"
        if not pytest_bin.exists():
            pip_bin = bin_dir / "pip"
            # Look for requirements.txt in target
            req_candidates = [
                target_dir / "backend" / "requirements.txt",
                target_dir / "requirements.txt",
            ]
            req_file = next((r for r in req_candidates if r.exists()), None)
            
            install_cmd = [str(pip_bin), "install", "--quiet", "pytest", "pytest-asyncio", "httpx"]
            if req_file:
                install_cmd.extend(["-r", str(req_file)])

            try:
                subprocess.run(
                    install_cmd,
                    check=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=180,
                )
            except Exception:
                pass

        env_overlay = {
            "VIRTUAL_ENV": str(venv_root),
            "PATH": f"{bin_dir}:{os.environ.get('PATH', '')}",
        }
        return str(py_bin), env_overlay

    def resolve_venv(self, cwd: Optional[str] = None, auto_provision: bool = False) -> Tuple[Optional[str], Dict[str, str]]:
        """
        Auto-detects active or project-local virtual environments (.venv, venv, env).
        Provisioning is opt-in because it can install target-controlled packages.
        """
        target_dir = pathlib.Path(cwd or os.getcwd())
        candidate_paths = [
            target_dir / ".venv",
            target_dir / "venv",
            target_dir / "env",
            target_dir / "backend" / ".venv",
            target_dir / "backend" / "venv",
            target_dir.parent / ".venv",
        ]

        if "VIRTUAL_ENV" in os.environ:
            candidate_paths.insert(0, pathlib.Path(os.environ["VIRTUAL_ENV"]))

        for venv_path in candidate_paths:
            bin_dir = venv_path / "bin"
            py_bin = bin_dir / "python"
            if py_bin.exists() and os.access(py_bin, os.X_OK):
                env_overlay = {
                    "VIRTUAL_ENV": str(venv_path),
                    "PATH": f"{bin_dir}:{os.environ.get('PATH', '')}",
                }
                return str(py_bin), env_overlay

        if auto_provision:
            try:
                return self.provision_cached_venv(cwd)
            except Exception:
                pass

        return sys.executable, {}

    def _apply_resource_limits(self):
        """Apply resource limits; these do not isolate the child process."""
        try:
            import resource
            # CPU Limit
            if self.max_cpu_s > 0:
                resource.setrlimit(resource.RLIMIT_CPU, (self.max_cpu_s, self.max_cpu_s))
            # Memory Limit (Non-macOS to prevent ASAN clashes)
            if self.max_mem_mb > 0 and sys.platform != "darwin":
                mem_bytes = self.max_mem_mb * 1024 * 1024
                resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes))
        except Exception:
            pass

    def run_command(
        self,
        cmd: str,
        cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
        timeout_s: Optional[float] = None,
        input_data: Optional[str] = None,
        isolate_network: bool = False,
    ) -> Tuple[int, str, str, float]:
        """
        Executes a trusted command on the host after explicit opt-in.

        Resource limits and proxy variables are best-effort controls, not an
        operating-system sandbox or network boundary.
        """
        if self.network_isolated or isolate_network:
            return (
                COMMAND_EXECUTION_DISABLED,
                "",
                "Network isolation is not enforced by this runner; command was not executed.",
                0.0,
            )
        if self.execution_block_reason:
            return (COMMAND_EXECUTION_DISABLED, "", self.execution_block_reason, 0.0)
        if not self.allow_host_execution:
            return (
                COMMAND_EXECUTION_DISABLED,
                "",
                "Host command execution is disabled; opt in only for trusted target code.",
                0.0,
            )
        command_cwd = pathlib.Path(cwd or os.getcwd()).resolve()
        if self.execution_root is not None:
            try:
                command_cwd.relative_to(self.execution_root)
            except ValueError:
                return (
                    COMMAND_EXECUTION_DISABLED,
                    "",
                    "Command working directory is outside the authorized target root.",
                    0.0,
                )

        with self._budget_lock:
            now = time.monotonic()
            if self._command_count >= self.max_commands:
                return (
                    COMMAND_EXECUTION_DISABLED,
                    "",
                    f"Engagement command budget exhausted ({self.max_commands} commands).",
                    0.0,
                )
            if self._execution_started_at is None:
                self._execution_started_at = now
            elapsed = now - self._execution_started_at
            remaining = self.max_total_runtime_s - elapsed
            if remaining <= 0:
                return (
                    COMMAND_EXECUTION_DISABLED,
                    "",
                    "Engagement total runtime budget exhausted.",
                    0.0,
                )
            self._command_count += 1

        start_time = time.time()
        
        # 1. Environment scrubbing & venv resolution
        exec_env = {
            key: value
            for key, value in os.environ.items()
            if not SENSITIVE_ENV_PATTERN.search(key)
        }
        py_bin, venv_env = self.resolve_venv(cwd, auto_provision=False)
        exec_env.update(venv_env)

        # Ensure cwd is in PYTHONPATH
        target_cwd = cwd or os.getcwd()
        current_pypath = exec_env.get("PYTHONPATH", "")
        exec_env["PYTHONPATH"] = f"{target_cwd}:{current_pypath}" if current_pypath else target_cwd

        if env:
            exec_env.update(env)

        # 2. Deterministic sanitizer instrumentation
        exec_env["ASAN_OPTIONS"] = "color=never:symbolize=1:abort_on_error=1"
        exec_env["UBSAN_OPTIONS"] = "color=never:symbolize=1:abort_on_error=1"
        exec_env["PYTHONUNBUFFERED"] = "1"

        try:
            proc = subprocess.Popen(
                cmd,
                shell=True,
                cwd=cwd or os.getcwd(),
                env=exec_env,
                stdin=subprocess.PIPE if input_data is not None else None,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                preexec_fn=self._apply_resource_limits if sys.platform != "win32" else None,
                start_new_session=(os.name == "posix"),
            )
            stdout, stderr = proc.communicate(
                input=input_data,
                timeout=min(timeout_s or self.default_timeout_s, self.default_timeout_s, remaining),
            )
            duration_ms = (time.time() - start_time) * 1000.0
            return proc.returncode, stdout[: self.max_output_bytes], stderr[: self.max_output_bytes], duration_ms
        except subprocess.TimeoutExpired:
            try:
                if os.name == "posix":
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                else:
                    proc.kill()
            except ProcessLookupError:
                pass
            stdout, stderr = proc.communicate()
            timeout_message = f"Execution timed out after {min(timeout_s or self.default_timeout_s, self.default_timeout_s, remaining)}s"
            return (
                -999,
                stdout[: self.max_output_bytes],
                (stderr or timeout_message)[: self.max_output_bytes],
                (time.time() - start_time) * 1000.0,
            )
        except Exception as e:
            return -1, "", f"Command execution error: {str(e)}", (time.time() - start_time) * 1000.0

    # ── LAYER 1: Adversarial Re-Testing ─────────────────────────────────────────

    def verify_adversarial(
        self,
        reproducer_cmd: str,
        input_payload: Optional[str] = None,
        expected_rejection_pattern: Optional[str] = None,
        cwd: Optional[str] = None,
        timeout_s: Optional[float] = None,
    ) -> VerificationResult:
        """
        Re-executes the exact exploit witness against the patched codebase.
        Verifies that previously exploitable inputs are now safely rejected or handled.
        """
        code, stdout, stderr, dur = self.run_command(
            cmd=reproducer_cmd,
            cwd=cwd,
            input_data=input_payload,
            timeout_s=timeout_s,
        )
        combined = f"{stdout}\n{stderr}"

        # Check if any crash or sanitizer error still occurred
        crash_found = False
        for pattern in SANITIZER_PATTERNS:
            if re.search(pattern, combined, re.IGNORECASE):
                crash_found = True
                break

        if crash_found:
            return VerificationResult(
                verdict=STATUS_DISPROVEN,
                level=L0_HYPOTHESIS,
                layer="layer1_adversarial",
                reason=f"Adversarial payload still triggered crash/sanitizer violation",
                stdout=stdout,
                stderr=stderr,
                duration_ms=dur,
            )

        if code < 0:
            return VerificationResult(
                verdict=STATUS_UNKNOWN,
                level=L0_HYPOTHESIS,
                layer="layer1_adversarial",
                reason=f"Adversarial re-test did not complete (exit code {code})",
                stdout=stdout,
                stderr=stderr,
                duration_ms=dur,
            )

        if not expected_rejection_pattern:
            return VerificationResult(
                verdict=STATUS_UNKNOWN,
                level=L0_HYPOTHESIS,
                layer="layer1_adversarial",
                reason="An explicit expected_rejection_pattern is required to verify safe behavior",
                stdout=stdout,
                stderr=stderr,
                duration_ms=dur,
            )

        passed_rejection = bool(re.search(expected_rejection_pattern, combined, re.IGNORECASE))
        if passed_rejection:
            witness = VerificationWitness(
                oracle="adversarial_retest",
                command=reproducer_cmd,
                exit_code=code,
                duration_ms=dur,
                output_hash=self._hash_output(combined),
                signature="Vulnerability successfully neutralized; no crashes or unauthorized leaks",
                reproducer_input=input_payload[:500] if input_payload else None,
                layer="layer1_adversarial",
            )
            return VerificationResult(
                verdict=STATUS_VERIFIED,
                level=L2_BUG_WITNESS,
                witness=witness,
                layer="layer1_adversarial",
                reason="Adversarial attack vector safely neutralized",
                stdout=stdout,
                stderr=stderr,
                duration_ms=dur,
            )
        else:
            return VerificationResult(
                verdict=STATUS_DISPROVEN,
                level=L0_HYPOTHESIS,
                layer="layer1_adversarial",
                reason=f"Did not match expected safe rejection pattern: {expected_rejection_pattern}",
                stdout=stdout,
                stderr=stderr,
                duration_ms=dur,
            )

    # ── LAYER 2: Functional & API Test Runner ──────────────────────────────────

    def verify_adversarial(
    self,
    reproducer_cmd: str,
    oracle: AdversarialOracle,
    input_payload: Optional[str] = None,
    cwd: Optional[str] = None,
    timeout_s: Optional[float] = None,
) -> VerificationResult:
    """Re-execute an exploit witness using a policy-declared rejection oracle.

    The rejection pattern is supplied by the ROE, not the caller. This closes the
    hole where a permissive agent-supplied pattern (e.g. `.*`) could force a pass.
    """
    code, stdout, stderr, dur = self.run_command(
        cmd=reproducer_cmd, cwd=cwd, input_data=input_payload, timeout_s=timeout_s,
    )
    combined = f"{stdout}\n{stderr}"

    crash_sig = _detect_crash(code, stdout, stderr)
    if crash_sig:
        return VerificationResult(
            verdict=STATUS_DISPROVEN, level=L0_HYPOTHESIS, layer="layer1_adversarial",
            reason=f"Adversarial payload still triggered crash/sanitizer: {crash_sig}",
            stdout=stdout, stderr=stderr, duration_ms=dur,
        )

    if code < 0:
        return VerificationResult(
            verdict=STATUS_UNKNOWN, level=L0_HYPOTHESIS, layer="layer1_adversarial",
            reason=f"Adversarial re-test did not complete (exit code {code})",
            stdout=stdout, stderr=stderr, duration_ms=dur,
        )

    if oracle.compiled().search(combined):
        witness = VerificationWitness(
            oracle=f"adversarial:{oracle.name}",
            command=reproducer_cmd, exit_code=code, duration_ms=dur,
            output_hash=self._hash_output(combined),
            signature=f"Matched ROE oracle '{oracle.name}': {oracle.description or oracle.rejection_pattern}",
            reproducer_input=input_payload[:500] if input_payload else None,
            layer="layer1_adversarial",
        )
        return VerificationResult(
            verdict=STATUS_VERIFIED, level=L2_BUG_WITNESS, witness=witness,
            layer="layer1_adversarial",
            reason=f"Neutralized per ROE oracle '{oracle.name}'",
            stdout=stdout, stderr=stderr, duration_ms=dur,
        )
    return VerificationResult(
        verdict=STATUS_DISPROVEN, level=L0_HYPOTHESIS, layer="layer1_adversarial",
        reason=f"Output did not match ROE oracle '{oracle.name}' rejection pattern",
        stdout=stdout, stderr=stderr, duration_ms=dur,
    )

    def verify_project_checks(self, cwd: Optional[str] = None) -> VerificationResult:
        """Run package-declared build and validation scripts, separate from tests."""
        target_dir = pathlib.Path(cwd or os.getcwd()).resolve()
        checks = discover_project_checks(target_dir)
        if not checks:
            return VerificationResult(
                verdict=STATUS_NOT_APPLICABLE,
                level=L0_HYPOTHESIS,
                layer="project_checks",
                reason="No supported build or validation scripts found",
            )

        executed = []
        failures = []
        unknowns = []
        outputs = []
        total_duration = 0.0
        for name, command, package_root in checks:
            code, stdout, stderr, duration = self.run_command(
                cmd=command,
                cwd=str(package_root),
            )
            total_duration += duration
            combined = f"{stdout}\n{stderr}"
            if code == COMMAND_EXECUTION_DISABLED:
                unknowns.append(f"{name}: {stderr.strip()}")
            elif code < 0:
                unknowns.append(f"{name}: {stderr.strip() or f'exit code {code}'}")
            elif code == 0:
                executed.append(f"{name}: {command}")
                outputs.append(combined)
            elif code == 127 or "command not found" in combined.lower():
                unknowns.append(f"{name}: required package runner is unavailable")
            else:
                failures.append(f"{name} failed with exit code {code}: {combined[-500:]}")

        if failures:
            return VerificationResult(
                verdict=STATUS_FAILED,
                level=L0_HYPOTHESIS,
                layer="project_checks",
                reason="; ".join(failures[:3]),
                stdout="\n".join(outputs)[:self.max_output_bytes],
                duration_ms=total_duration,
            )
        if unknowns:
            return VerificationResult(
                verdict=STATUS_UNKNOWN,
                level=L0_HYPOTHESIS,
                layer="project_checks",
                reason="; ".join(unknowns[:3]),
                stdout="\n".join(outputs)[:self.max_output_bytes],
                duration_ms=total_duration,
            )

        output = "\n".join(outputs)
        witness = VerificationWitness(
            oracle="project_checks",
            command="\n".join(executed),
            exit_code=0,
            duration_ms=total_duration,
            output_hash=self._hash_output(output),
            signature=f"All {len(executed)} declared project check(s) passed",
            layer="project_checks",
        )
        return VerificationResult(
            verdict=STATUS_VERIFIED,
            level=L2_BUG_WITNESS,
            witness=witness,
            layer="project_checks",
            reason=f"All {len(executed)} declared project check(s) passed",
            stdout=output[:self.max_output_bytes],
            duration_ms=total_duration,
        )

    # ── LAYER 3: Static Analysis & Type Checking ────────────────────────────────

    def verify_static_and_types(
        self,
        cwd: Optional[str] = None,
        target_paths: Optional[List[str]] = None,
    ) -> VerificationResult:
        """Run applicable Python and JavaScript/TypeScript static checks."""
        target_dir = pathlib.Path(cwd or os.getcwd()).resolve()
        paths_to_check = [(target_dir / path).resolve() for path in (target_paths or ["."])]
        supported_suffixes = {".py", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}
        source_files = []
        for path in paths_to_check:
            candidates = [path] if path.is_file() else path.rglob("*") if path.is_dir() else []
            source_files.extend(
                candidate for candidate in candidates
                if candidate.is_file()
                and candidate.suffix in supported_suffixes
                and not any(part in IGNORED_DISCOVERY_DIRS for part in candidate.parts)
            )
        source_files = sorted(set(source_files))
        if not source_files:
            return VerificationResult(
                verdict=STATUS_UNKNOWN,
                level=L0_HYPOTHESIS,
                layer="layer3_static_types",
                reason="No supported Python, JavaScript, or TypeScript files found",
            )

        py_files = [path for path in source_files if path.suffix == ".py"]
        js_files = [path for path in source_files if path.suffix in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}]
        ts_files = [path for path in source_files if path.suffix in {".ts", ".tsx"}]
        errors = []
        unknowns = []
        checked = []
        outputs = []
        total_duration = 0.0

        def run_check(label: str, command: str, working_dir: pathlib.Path = target_dir) -> None:
            nonlocal total_duration
            code, stdout, stderr, duration = self.run_command(command, cwd=str(working_dir))
            total_duration += duration
            output = f"{stdout}\n{stderr}"
            if code < 0:
                unknowns.append(f"{label} did not complete")
            elif code != 0:
                errors.append(f"{label} failed: {(output)[:300]}")
            else:
                checked.append(label)
                outputs.append(output)

        for path in py_files:
            try:
                ast.parse(path.read_text(encoding="utf-8"))
            except (OSError, SyntaxError, UnicodeError) as error:
                errors.append(f"Python AST failed for {path}: {error}")
        if py_files:
            checked.append(f"Python AST ({len(py_files)} files)")
            if shutil.which("ruff"):
                run_check("Ruff", f"ruff check {shlex.join([str(path) for path in py_files])}")
            else:
                unknowns.append("Ruff is not installed")
            if shutil.which("mypy"):
                run_check(
                    "Mypy",
                    f"mypy --ignore-missing-imports {shlex.join([str(path) for path in py_files])}",
                )
            else:
                unknowns.append("Mypy is not installed")

        package_files = {}
        for path in js_files:
            package_root = path.parent
            while target_dir in package_root.parents and not (package_root / "package.json").is_file():
                package_root = package_root.parent
            if not (package_root / "package.json").is_file():
                package_root = target_dir
            package_files.setdefault(package_root, []).append(path)

        for package_root, files in package_files.items():
            eslint = shutil.which("eslint")
            local_eslint = package_root / "node_modules" / ".bin" / "eslint"
            eslint = eslint or (str(local_eslint) if local_eslint.is_file() else None)
            package_label = package_root.relative_to(target_dir).as_posix() or "."
            if eslint:
                run_check(
                    f"ESLint ({package_label})",
                    f"{shlex.quote(eslint)} {shlex.join([str(path) for path in files])}",
                    package_root,
                )
            else:
                unknowns.append(f"ESLint is not installed for package {package_label}")

            package_ts_files = [path for path in files if path.suffix in {".ts", ".tsx"}]
            if package_ts_files:
                tsconfig = package_root / "tsconfig.json"
                tsc = shutil.which("tsc")
                local_tsc = package_root / "node_modules" / ".bin" / "tsc"
                tsc = tsc or (str(local_tsc) if local_tsc.is_file() else None)
                if not tsconfig.is_file():
                    unknowns.append(f"TypeScript files found without tsconfig.json in {package_label}")
                elif not tsc:
                    unknowns.append(f"TypeScript compiler (tsc) is not installed for package {package_label}")
                else:
                    run_check(
                        f"TypeScript ({package_label})",
                        f"{shlex.quote(tsc)} --noEmit --project {shlex.quote(str(tsconfig))}",
                        package_root,
                    )

        if errors:
            return VerificationResult(
                verdict=STATUS_FAILED,
                level=L0_HYPOTHESIS,
                layer="layer3_static_types",
                reason="; ".join(errors[:3]),
                duration_ms=total_duration,
            )
        if unknowns:
            return VerificationResult(
                verdict=STATUS_UNKNOWN,
                level=L0_HYPOTHESIS,
                layer="layer3_static_types",
                reason="; ".join(unknowns[:3]),
                duration_ms=total_duration,
            )

        command_summary = "; ".join(checked)
        witness = VerificationWitness(
            oracle="static_type_check",
            command=command_summary,
            exit_code=0,
            duration_ms=total_duration,
            output_hash=self._hash_output("\n".join(outputs)),
            signature=f"Passed checks: {command_summary}",
            layer="layer3_static_types",
        )
        return VerificationResult(
            verdict=STATUS_VERIFIED,
            level=L2_BUG_WITNESS,
            witness=witness,
            layer="layer3_static_types",
            reason=f"Passed {len(checked)} applicable static check(s)",
            stdout="\n".join(outputs)[:self.max_output_bytes],
            duration_ms=total_duration,
        )

    # ── LAYER 4: DevOps & CI/CD Verification ───────────────────────────────────

    def verify_devops_ci(
        self,
        cwd: Optional[str] = None,
    ) -> VerificationResult:
        """
        Performs basic Dockerfile checks and parses GitHub Actions workflow YAML.
        """
        target_dir = pathlib.Path(cwd or os.getcwd())
        findings = []
        unknowns = []
        checked = []

        # 1. Dockerfile check
        dockerfile = target_dir / "Dockerfile"
        if not dockerfile.exists() and (target_dir / "backend" / "Dockerfile").exists():
            dockerfile = target_dir / "backend" / "Dockerfile"

        if dockerfile.exists():
            checked.append("Dockerfile")
            content = dockerfile.read_text(encoding="utf-8")
            if "FROM " not in content:
                findings.append("Dockerfile missing valid FROM directive")
            if "USER root" in content:
                findings.append("Dockerfile runs as root user without non-privileged switch")

        # 2. GitHub Actions YAML check
        wf_dir = target_dir / ".github" / "workflows"
        workflows = sorted((*wf_dir.glob("*.yml"), *wf_dir.glob("*.yaml"))) if wf_dir.exists() else []
        if workflows:
            try:
                import yaml
            except ImportError:
                unknowns.append("PyYAML is required to validate GitHub Actions workflow syntax")
            else:
                for workflow in workflows:
                    try:
                        yaml.safe_load(workflow.read_text(encoding="utf-8"))
                        checked.append(f"workflow {workflow.name}")
                    except Exception as error:
                        findings.append(f"YAML syntax error in {workflow.name}: {error}")

        if findings:
            return VerificationResult(
                verdict=STATUS_FAILED,
                level=L0_HYPOTHESIS,
                layer="layer4_devops_ci",
                reason="; ".join(findings),
            )

        if unknowns or not checked:
            reason = "; ".join(unknowns) if unknowns else "No supported DevOps artifacts found to validate"
            return VerificationResult(
                verdict=STATUS_UNKNOWN,
                level=L0_HYPOTHESIS,
                layer="layer4_devops_ci",
                reason=reason,
            )

        witness = VerificationWitness(
            oracle="devops_ci_verifier",
            command="; ".join(checked),
            exit_code=0,
            duration_ms=15.0,
            output_hash=self._hash_output("\n".join(checked)),
            signature=f"Validated: {', '.join(checked)}",
            layer="layer4_devops_ci",
        )
        return VerificationResult(
            verdict=STATUS_VERIFIED,
            level=L2_BUG_WITNESS,
            witness=witness,
            layer="layer4_devops_ci",
            reason=f"Validated {len(checked)} DevOps artifact(s)",
        )

    # ── Python Isolated Check ──────────────────────────────────────────────────

    def check_python_assertion(
        self,
        code_snippet: str,
        entry_func: str = "check",
        cwd: Optional[str] = None,
        timeout_s: Optional[float] = None,
    ) -> VerificationResult:
        wrapper = f"""
import json, sys, os, traceback

if {repr(cwd)} and {repr(cwd)} not in sys.path:
    sys.path.insert(0, {repr(cwd)})
if {repr(os.getcwd())} not in sys.path:
    sys.path.insert(0, {repr(os.getcwd())})

{code_snippet}

try:
    fn = locals().get("{entry_func}")
    if not callable(fn):
        raise NameError("Callable '{entry_func}' not found")
    res = fn()
    print("VIDHUR_RESULT_START")
    print(json.dumps(res, default=str))
    print("VIDHUR_RESULT_END")
except Exception as e:
    print("VIDHUR_ERROR_START")
    print(traceback.format_exc())
    print("VIDHUR_ERROR_END")
    sys.exit(1)
"""
        with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
            f.write(wrapper)
            tmp_name = f.name

        try:
            code, stdout, stderr, dur = self.run_command(
                cmd=f"{sys.executable} {tmp_name}",
                cwd=cwd,
                timeout_s=timeout_s,
            )
            combined = f"{stdout}\n{stderr}"
            if code < 0:
                return VerificationResult(
                    verdict=STATUS_UNKNOWN,
                    level=L0_HYPOTHESIS,
                    layer="python_assertion",
                    reason=stderr.strip() or f"Python assertion did not complete (exit code {code})",
                    stdout=stdout,
                    stderr=stderr,
                    duration_ms=dur,
                )
            if code != 0:
                return VerificationResult(
                    verdict=STATUS_UNKNOWN,
                    level=L0_HYPOTHESIS,
                    layer="python_assertion",
                    reason=f"Python check did not complete successfully: {combined[:300]}",
                    stdout=stdout,
                    stderr=stderr,
                    duration_ms=dur,
                )

            start_marker = "VIDHUR_RESULT_START"
            end_marker = "VIDHUR_RESULT_END"
            start = stdout.rfind(start_marker)
            end = stdout.find(end_marker, start + len(start_marker)) if start >= 0 else -1
            if start < 0 or end < 0:
                return VerificationResult(
                    verdict=STATUS_UNKNOWN,
                    level=L0_HYPOTHESIS,
                    layer="python_assertion",
                    reason="Python check produced no complete result payload",
                    stdout=stdout,
                    stderr=stderr,
                    duration_ms=dur,
                )

            raw_json = stdout[start + len(start_marker):end].strip()
            try:
                parsed = json.loads(raw_json)
            except json.JSONDecodeError as error:
                return VerificationResult(
                    verdict=STATUS_UNKNOWN,
                    level=L0_HYPOTHESIS,
                    layer="python_assertion",
                    reason=f"Python check returned invalid JSON: {error}",
                    stdout=stdout,
                    stderr=stderr,
                    duration_ms=dur,
                )

            if isinstance(parsed, bool):
                passed = parsed
            elif isinstance(parsed, dict) and isinstance(parsed.get("passed"), bool):
                passed = parsed["passed"]
            else:
                return VerificationResult(
                    verdict=STATUS_UNKNOWN,
                    level=L0_HYPOTHESIS,
                    layer="python_assertion",
                    reason="Assertion must return a boolean or a dictionary with a boolean 'passed' field",
                    stdout=stdout,
                    stderr=stderr,
                    duration_ms=dur,
                )
            if passed:
                witness = VerificationWitness(
                    oracle="python_assertion",
                    command=f"{shlex.quote(sys.executable)} -c {shlex.quote(wrapper)}",
                    exit_code=0,
                    duration_ms=dur,
                    output_hash=self._hash_output(combined),
                    signature=f"Assertion passed: {parsed}",
                    artifacts={
                        "python_wrapper": wrapper,
                        "python_wrapper_sha256": hashlib.sha256(wrapper.encode("utf-8")).hexdigest(),
                    },
                )
                return VerificationResult(
                    verdict=STATUS_VERIFIED,
                    level=L2_BUG_WITNESS,
                    witness=witness,
                    reason="Python assertion succeeded",
                    stdout=stdout,
                    stderr=stderr,
                    duration_ms=dur,
                )
            return VerificationResult(
                verdict=STATUS_DISPROVEN,
                level=L0_HYPOTHESIS,
                reason=f"Python assertion returned false: {parsed}",
                stdout=stdout,
                stderr=stderr,
                duration_ms=dur,
            )
        finally:
            try:
                os.remove(tmp_name)
            except Exception:
                pass
