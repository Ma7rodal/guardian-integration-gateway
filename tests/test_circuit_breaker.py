import pytest

from app.circuit_breaker import CircuitBreaker, CircuitOpenError, CircuitState


class FakeClock:
    def __init__(self, initial: float = 100.0) -> None:
        self.now = initial

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


async def _succeed() -> str:
    return "ok"


async def _fail() -> str:
    raise RuntimeError("boom")


@pytest.mark.asyncio
async def test_opens_after_three_consecutive_failures():
    clock = FakeClock()
    cb = CircuitBreaker(failure_threshold=3, recovery_timeout_seconds=30.0, clock=clock)

    for _ in range(3):
        with pytest.raises(RuntimeError):
            await cb.call(_fail)

    assert cb.snapshot()["state"] == CircuitState.OPEN.value

    # 4th call must fail fast with CircuitOpenError without executing _succeed
    called = False

    async def _should_not_run() -> str:
        nonlocal called
        called = True
        return "unexpected"

    with pytest.raises(CircuitOpenError) as exc_info:
        await cb.call(_should_not_run)

    assert called is False
    assert exc_info.value.retry_after_seconds == 30.0


@pytest.mark.asyncio
async def test_success_resets_failure_counter():
    clock = FakeClock()
    cb = CircuitBreaker(failure_threshold=3, recovery_timeout_seconds=30.0, clock=clock)

    for _ in range(2):
        with pytest.raises(RuntimeError):
            await cb.call(_fail)

    assert await cb.call(_succeed) == "ok"
    assert cb.snapshot()["consecutive_failures"] == 0
    assert cb.snapshot()["state"] == CircuitState.CLOSED.value

    # Two more failures should still keep circuit CLOSED
    for _ in range(2):
        with pytest.raises(RuntimeError):
            await cb.call(_fail)
    assert cb.snapshot()["state"] == CircuitState.CLOSED.value


@pytest.mark.asyncio
async def test_half_open_recovery_and_reopen_on_failure():
    clock = FakeClock()
    cb = CircuitBreaker(failure_threshold=3, recovery_timeout_seconds=10.0, clock=clock)

    for _ in range(3):
        with pytest.raises(RuntimeError):
            await cb.call(_fail)

    assert cb.snapshot()["state"] == CircuitState.OPEN.value

    # Advance past cooldown -> HALF_OPEN probe fails -> immediately re-opens
    clock.advance(11.0)
    assert cb.snapshot()["state"] == CircuitState.HALF_OPEN.value
    with pytest.raises(RuntimeError):
        await cb.call(_fail)
    assert cb.snapshot()["state"] == CircuitState.OPEN.value

    # Advance past cooldown again -> HALF_OPEN probe succeeds -> CLOSED
    clock.advance(11.0)
    assert await cb.call(_succeed) == "ok"
    assert cb.snapshot()["state"] == CircuitState.CLOSED.value
    assert cb.snapshot()["consecutive_failures"] == 0
