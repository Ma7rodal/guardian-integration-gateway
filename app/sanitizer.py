import re
from dataclasses import dataclass
from typing import Dict, List

from presidio_analyzer import (
    AnalyzerEngine,
    Pattern,
    PatternRecognizer,
    RecognizerRegistry,
)
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_analyzer.predefined_recognizers import (
    CreditCardRecognizer,
    EmailRecognizer,
    UsSsnRecognizer,
)
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

TARGET_ENTITIES: List[str] = ["CREDIT_CARD", "EMAIL_ADDRESS", "US_SSN"]

ENTITY_TO_LABEL: Dict[str, str] = {
    "CREDIT_CARD": "CREDIT_CARD",
    "EMAIL_ADDRESS": "EMAIL",
    "US_SSN": "SSN",
}

# Linear-time (ReDoS-safe) pre-filter: matches '@' (email candidate) or
# >= 9 digits allowing single spaces/hyphens (SSN or credit card candidate).
FAST_PATH_CANDIDATE_RE = re.compile(r"@|\d(?:[\s-]?\d){8,}")


@dataclass(frozen=True)
class SanitizationResult:
    sanitized_text: str
    redactions_count: int
    redacted_types: List[str]


class PresidioSanitizer:
    """Two-layer PII sanitizer combining a compiled regex fast-path with a
    minimalist, deterministic Microsoft Presidio engine (no neural NER).

    Layer 1 (Fast-Path):
        Skips Presidio completely (<0.1ms) when input has no '@' or >=9 digits.
    Layer 2 (Deterministic Presidio):
        Runs only CreditCardRecognizer (Luhn), EmailRecognizer, UsSsnRecognizer,
        and GuardianNineDigitSSNRecognizer, excluding SpacyRecognizer & 20+
        unused recognizers.
    """

    def __init__(self, spacy_model_name: str = "en_core_web_sm") -> None:
        nlp_configuration = {
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "en", "model_name": spacy_model_name}],
        }
        provider = NlpEngineProvider(nlp_configuration=nlp_configuration)
        nlp_engine = provider.create_engine()

        # Strip heavy neural components (ner, parser) since all registered
        # recognizers are deterministic (regex + Luhn) and only need tokens/lemmas.
        spacy_nlp = nlp_engine.nlp.get("en")
        if spacy_nlp is not None:
            for pipe_name in ("ner", "parser"):
                if spacy_nlp.has_pipe(pipe_name):
                    spacy_nlp.remove_pipe(pipe_name)

        # Minimalist registry: deterministic recognizers only (no SpacyRecognizer)
        registry = RecognizerRegistry()
        registry.add_recognizer(CreditCardRecognizer())
        registry.add_recognizer(EmailRecognizer())
        registry.add_recognizer(UsSsnRecognizer())

        # Custom recognizer ensures both formatted SSNs (XXX-XX-XXXX / XXX XX XXXX)
        # and raw 9-digit numeric sequences are reliably caught regardless of
        # surrounding language or context.
        strict_ssn_recognizer = PatternRecognizer(
            supported_entity="US_SSN",
            name="GuardianNineDigitSSNRecognizer",
            patterns=[
                Pattern(
                    name="ssn_delimited",
                    regex=r"\b\d{3}[-\s]\d{2}[-\s]\d{4}\b",
                    score=0.85,
                ),
                Pattern(
                    name="ssn_nine_digits",
                    regex=r"(?<!\d)\d{9}(?!\d)",
                    score=0.80,
                ),
            ],
        )
        registry.add_recognizer(strict_ssn_recognizer)

        self._analyzer = AnalyzerEngine(
            nlp_engine=nlp_engine,
            registry=registry,
            supported_languages=["en"],
        )
        self._anonymizer = AnonymizerEngine()
        self._operators: Dict[str, OperatorConfig] = {
            entity: OperatorConfig(
                "replace", {"new_value": f"<REDACTED: {label}>"}
            )
            for entity, label in ENTITY_TO_LABEL.items()
        }

    def sanitize(self, text: str) -> SanitizationResult:
        """Analyze and redact target PII entities from input text."""
        # Layer 1: Fast-Path bypass for messages with no PII candidates
        if not FAST_PATH_CANDIDATE_RE.search(text):
            return SanitizationResult(
                sanitized_text=text,
                redactions_count=0,
                redacted_types=[],
            )

        # Layer 2: Deterministic Presidio validation (Luhn, RFC email, 9-digit SSN)
        results = self._analyzer.analyze(
            text=text,
            entities=TARGET_ENTITIES,
            language="en",
        )

        if not results:
            return SanitizationResult(
                sanitized_text=text,
                redactions_count=0,
                redacted_types=[],
            )

        anonymized = self._anonymizer.anonymize(
            text=text,
            analyzer_results=results,
            operators=self._operators,
        )

        redacted_types = sorted(
            {
                ENTITY_TO_LABEL.get(item.entity_type, item.entity_type)
                for item in anonymized.items
            }
        )

        return SanitizationResult(
            sanitized_text=anonymized.text,
            redactions_count=len(anonymized.items),
            redacted_types=redacted_types,
        )
