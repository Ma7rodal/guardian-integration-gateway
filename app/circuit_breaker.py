import asyncio
import time
from enum import Enum
from typing import Awaitable, Callable, Optional, TypeVar

T = TypeVar("T")


class CircuitState(str, Enum):
    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"


class CircuitOpenError(Exception):
    """Raised immediately when the circuit breaker is OPEN."""

    def __init__(self, retry_after_seconds: float) -> None:
        self.retry_after_seconds = max(0.0, round(retry_after_seconds, 2))
        super().__init__(
            f"Circuit breaker is OPEN. Retry after {self.retry_after_seconds}s."
        )


class CircuitBreaker:
    """Async-safe 3-state Circuit Breaker (CLOSED -> OPEN -> HALF_OPEN).

    Opens after `failure_threshold` consecutive failures and immediately rejects
    subsequent calls until `recovery_timeout_seconds` elapses, then allows a
    single probe request in HALF_OPEN state.
    """

    def __init__(
        self,
        failure_threshold: int = 3,
        recovery_timeout_seconds: float = 30.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if failure_threshold < 1:
            raise ValueError("failure_threshold must be >= 1")
        if recovery_timeout_seconds <= 0:
            raise ValueError("recovery_timeout_seconds must be > 0")

        self.failure_threshold = failure_threshold
        self.recovery_timeout_seconds = recovery_timeout_seconds
        self._clock = clock

        self._state = CircuitState.CLOSED
        self._consecutive_failures = 0
        self._opened_at: Optional[float] = None
        self._half_open_probe_in_flight = False
        self._lock = asyncio.Lock()

    def _compute_retry_after(self) -> Optional[float]:
        if self._state != CircuitState.OPEN or self._opened_at is None:
            return None
        elapsed = self._clock() - self._opened_at
        remaining = self.recovery_timeout_seconds - elapsed
        return max(0.0, round(remaining, 2))

    def snapshot(self) -> dict:
        """Return a read-only telemetry snapshot of the breaker state."""
        state = self._state
        retry_after = self._compute_retry_after()
        if state == CircuitState.OPEN and retry_after == 0.0:
            state = CircuitState.HALF_OPEN
            retry_after = None

        return {
            "state": state.value,
            "consecutive_failures": self._consecutive_failures,
            "failure_threshold": self.failure_threshold,
            "retry_after_seconds": retry_after,
        }

    async def call(self, func: Callable[..., Awaitable[T]], *args, **kwargs) -> T:
        """Execute an async callable protected by the circuit breaker."""
        is_probe = False

        async with self._lock:
            if self._state == CircuitState.OPEN:
                retry_after = self._compute_retry_after() or 0.0
                if retry_after > 0.0:
                    raise CircuitOpenError(retry_after_seconds=retry_after)
                # Cooldown elapsed: transition to HALF_OPEN for a single probe
                self._state = CircuitState.HALF_OPEN
                self._half_open_probe_in_flight = True
                is_probe = True
            elif self._state == CircuitState.HALF_OPEN:
                if self._half_open_probe_in_flight:
                    raise CircuitOpenError(
                        retry_after_seconds=self.recovery_timeout_seconds
                    )
                self._half_open_probe_in_flight = True
                is_probe = True

        try:
            result = await func(*args, **kwargs)
        except Exception:
            async with self._lock:
                self._consecutive_failures += 1
                if is_probe or self._consecutive_failures >= self.failure_threshold:
                    self._state = CircuitState.OPEN
                    self._opened_at = self._clock()
                self._half_open_probe_in_flight = False
            raise
        else:
            async with self._lock:
                self._consecutive_failures = 0
                self._state = CircuitState.CLOSED
                self._opened_at = None
                self._half_open_probe_in_flight = False
            return result
