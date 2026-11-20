from typing import List, Optional
from pydantic import BaseModel, ConfigDict, Field


class InquiryRequest(BaseModel):
    """Payload accepted by POST /secure-inquiry."""

    model_config = ConfigDict(populate_by_name=True)

    user_id: str = Field(
        ...,
        alias="userId",
        min_length=1,
        max_length=128,
        description="Unique identifier of the requesting user.",
        examples=["user-42"],
    )
    message: str = Field(
        ...,
        min_length=1,
        max_length=10000,
        description="Raw user message that may contain sensitive PII.",
        examples=[
            "Hello! Please review my account jasson.rodriguez+vip@enterprise.io. "
            "Valid cards: Visa 4532-0151-1283-0366 and MasterCard 5425233430109903. "
            "Invalid Luhn tracking number (must NOT redact): 4532-0151-1283-0367. "
            "IDs: SSN 123-45-6789 and 9-digit code 987654321. "
            "Boundary IDs (must NOT redact): 8-digit order 12345678 and 10-digit phone 3001234567."
        ],
    )


class InquiryResponse(BaseModel):
    """Response returned by POST /secure-inquiry."""

    model_config = ConfigDict(populate_by_name=True)

    user_id: str = Field(..., alias="userId")
    sanitized_message: str = Field(..., alias="sanitizedMessage")
    answer: str
    redacted_types: List[str] = Field(default_factory=list, alias="redactedTypes")
    circuit_state: str = Field(..., alias="circuitState")
    latency_ms: float = Field(..., alias="latencyMs")
    retry_after_seconds: Optional[float] = Field(
        default=None, alias="retryAfterSeconds"
    )


class CircuitBreakerStatus(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    state: str
    consecutive_failures: int = Field(..., alias="consecutiveFailures")
    failure_threshold: int = Field(..., alias="failureThreshold")
    retry_after_seconds: Optional[float] = Field(
        default=None, alias="retryAfterSeconds"
    )


class HealthResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    status: str
    service: str
    version: str
    circuit_breaker: CircuitBreakerStatus = Field(..., alias="circuitBreaker")
