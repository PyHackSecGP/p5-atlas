"""Tool executor — runs shell commands with timeout, streams output, logs everything."""
from __future__ import annotations
import subprocess
import shlex
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path


class ToolResult:
    def __init__(self, command: str, stdout: str, stderr: str, returncode: int, elapsed: float):
        self.command   = command
        self.stdout    = stdout
        self.stderr    = stderr
        self.returncode = returncode
        self.elapsed   = elapsed

    @property
    def output(self) -> str:
        return (self.stdout + self.stderr).strip()

    @property
    def success(self) -> bool:
        return self.returncode == 0

    def __repr__(self) -> str:
        return f"ToolResult(cmd={self.command!r}, rc={self.returncode}, len={len(self.output)})"


def run(command: str | list[str], timeout: int = 300,
        cwd: str | None = None, log_dir: str | None = None,
        on_output=None) -> ToolResult:
    """Run a command. on_output(line) called per stdout line if provided."""
    if isinstance(command, str):
        cmd = shlex.split(command)
        cmd_str = command
    else:
        cmd = command
        cmd_str = " ".join(command)

    t0 = time.time()
    stdout_lines: list[str] = []
    stderr_buf = ""

    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, cwd=cwd,
        )

        # Stream stdout line by line
        for line in proc.stdout:
            stdout_lines.append(line)
            if on_output:
                on_output(line.rstrip())

        proc.wait(timeout=max(1, timeout - int(time.time() - t0)))
        stderr_buf = proc.stderr.read()
        rc = proc.returncode

    except subprocess.TimeoutExpired:
        proc.kill()
        stdout_lines.append("[TIMEOUT]")
        rc = -1
    except FileNotFoundError:
        return ToolResult(cmd_str, "", f"Command not found: {cmd[0]}", 127, 0)

    elapsed = time.time() - t0
    stdout = "".join(stdout_lines)
    result = ToolResult(cmd_str, stdout, stderr_buf, rc, elapsed)

    if log_dir:
        tool_name = cmd[0].split("/")[-1]
        safe = cmd_str.replace("/", "_").replace(" ", "_")[:60]
        log_path = Path(log_dir) / f"{tool_name}_{safe}.txt"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(f"CMD: {cmd_str}\nRC: {rc}\n\n{result.output}")

    return result


def run_parallel(
    tasks: list[dict],
    max_workers: int = 6,
) -> dict[str, "ToolResult"]:
    """Run multiple commands concurrently. Each task dict:
      name (str), command (str|list), timeout (int), log_dir (str), cwd (str)
    Returns {name: ToolResult} in completion order.
    on_output is omitted per-task since interleaved output is unreadable;
    results are available on the returned ToolResult objects.
    """
    _print_lock = threading.Lock()

    def _run_task(task: dict) -> tuple[str, ToolResult]:
        name = task["name"]
        result = run(
            command=task["command"],
            timeout=task.get("timeout", 300),
            cwd=task.get("cwd"),
            log_dir=task.get("log_dir"),
            on_output=None,  # suppress live interleaved output
        )
        with _print_lock:
            status = "✓" if result.success else "✗"
            print(f"  [{status}] {name} ({result.elapsed:.1f}s)")
        return name, result

    results: dict[str, ToolResult] = {}
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(_run_task, task): task["name"] for task in tasks}
        for future in as_completed(futures):
            name, result = future.result()
            results[name] = result
    return results


def run_background(command: str, log_path: str) -> subprocess.Popen:
    """Start a long-running process in the background."""
    Path(log_path).parent.mkdir(parents=True, exist_ok=True)
    log_f = open(log_path, "w")
    proc = subprocess.Popen(
        shlex.split(command), stdout=log_f, stderr=log_f, text=True,
    )
    return proc
