import asyncio


class AIServiceError(RuntimeError):
    """Raised when the simulated external AI provider fails."""


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
