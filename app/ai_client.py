import asyncio
from typing import Protocol, runtime_checkable


class AIServiceError(RuntimeError):
    """Raised when the external AI provider fails."""


@runtime_checkable
class AIClient(Protocol):
    """Strategy interface for downstream AI providers."""

    async def generate_answer(
        self, sanitized_message: str, simulate_failure: bool = False
    ) -> str: ...


class MockAIClient:
    """Simulates an external AI call with configurable async latency."""

    def __init__(self, delay_seconds: float = 2.0) -> None:
        self.delay_seconds = delay_seconds

    async def generate_answer(
        self, sanitized_message: str, simulate_failure: bool = False
    ) -> str:
        """Simulate an external AI provider call (default 2-second delay)."""
        await asyncio.sleep(self.delay_seconds)

        if simulate_failure:
            raise AIServiceError("Simulated upstream AI provider failure.")

        return "Generated Answer"
