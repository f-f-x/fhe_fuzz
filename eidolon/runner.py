"""Reusable, crash-safe JSON-line process runner for native FHE adaptors.

Native FHE set-up is expensive (parameters, keys, evaluation keys).  A target
therefore owns a long-lived helper process rather than rebuilding that state
for every generated expression.  The runner deliberately does *not* use
``communicate`` or pipe EOF as a liveness oracle: an abort handler can leave a
descendant holding a pipe descriptor.  ``waitpid(WNOHANG)`` and a real deadline
are authoritative, matching the isolation rules used by :mod:`engine`.
"""
from __future__ import annotations

import json
import os
import select
import signal
import subprocess
import time
from dataclasses import dataclass


@dataclass
class RunnerFailure(RuntimeError):
    kind: str
    detail: str

    def __str__(self) -> str:
        return self.detail


class JsonLineRunner:
    """One serialized request at a time to a restartable helper process."""

    def __init__(self, command: list[str], *, cwd: str, env: dict[str, str],
                 timeout: float = 45.0):
        self.command = command
        self.cwd = cwd
        self.env = env
        self.timeout = timeout
        self.proc: subprocess.Popen[bytes] | None = None
        self._stdout = bytearray()
        self._stderr = bytearray()
        self.restarts = 0

    def start(self) -> None:
        if self.proc is not None and self._alive():
            return
        self.close()
        self.proc = subprocess.Popen(
            self.command, cwd=self.cwd, env=self.env, stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0,
        )
        self._stdout.clear()
        self._stderr.clear()
        self.restarts += 1

    def _alive(self) -> bool:
        if self.proc is None:
            return False
        try:
            pid, _ = os.waitpid(self.proc.pid, os.WNOHANG)
        except ChildProcessError:
            return False
        return pid == 0

    def request(self, payload: dict) -> dict:
        self.start()
        assert self.proc is not None and self.proc.stdin and self.proc.stdout and self.proc.stderr
        try:
            os.write(self.proc.stdin.fileno(), json.dumps(payload).encode() + b"\n")
        except OSError as exc:
            self.close()
            raise RunnerFailure("write-failed", f"helper stdin write failed: {exc}") from exc

        out_fd = self.proc.stdout.fileno()
        err_fd = self.proc.stderr.fileno()
        deadline = time.monotonic() + self.timeout
        while True:
            # A dead child wins over the state of its pipes.  This avoids the
            # inherited-FD hang that originally affected the isolated runner.
            pid, status = os.waitpid(self.proc.pid, os.WNOHANG)
            if pid:
                detail = self._stderr.decode(errors="replace")[-2000:]
                self.proc = None
                if os.WIFSIGNALED(status):
                    raise RunnerFailure("signal", f"helper died by {signal.Signals(os.WTERMSIG(status)).name}: {detail}")
                raise RunnerFailure("process-exit", f"helper exited ({os.WEXITSTATUS(status)}): {detail}")
            if time.monotonic() >= deadline:
                self.close(kill=True)
                raise RunnerFailure("timeout", f"helper timed out after {self.timeout:g}s")

            ready, _, _ = select.select([out_fd, err_fd], [], [], 0.05)
            for fd in ready:
                try:
                    chunk = os.read(fd, 1 << 16)
                except BlockingIOError:
                    continue
                if fd == err_fd:
                    self._stderr.extend(chunk)
                    continue
                self._stdout.extend(chunk)
                if b"\n" not in self._stdout:
                    continue
                line, _, tail = self._stdout.partition(b"\n")
                self._stdout = bytearray(tail)
                try:
                    result = json.loads(line)
                except json.JSONDecodeError as exc:
                    self.close(kill=True)
                    raise RunnerFailure("bad-output", f"invalid helper JSON: {line[-1000:]!r}") from exc
                # A recovered Go panic still makes the in-helper FHE context
                # untrusted.  Tear it down so the next input uses fresh keys.
                if result.get("crash"):
                    self.close(kill=True)
                return result

    def close(self, *, kill: bool = False) -> None:
        if self.proc is None:
            return
        proc, self.proc = self.proc, None
        try:
            pid, _ = os.waitpid(proc.pid, os.WNOHANG)
        except ChildProcessError:
            pid = proc.pid
        if pid == 0:
            try:
                os.kill(proc.pid, signal.SIGKILL if kill else signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                os.waitpid(proc.pid, 0)
            except ChildProcessError:
                pass
        for stream in (proc.stdin, proc.stdout, proc.stderr):
            if stream:
                stream.close()
