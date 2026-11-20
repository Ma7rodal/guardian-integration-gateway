import pytest

from app.sanitizer import PresidioSanitizer


@pytest.fixture(scope="module")
def sanitizer() -> PresidioSanitizer:
    return PresidioSanitizer(spacy_model_name="en_core_web_sm")


def test_redacts_email(sanitizer: PresidioSanitizer):
    result = sanitizer.sanitize("Contact me at jane.doe+billing@company.co.uk please.")
    assert "<REDACTED: EMAIL>" in result.sanitized_text
    assert "jane.doe+billing@company.co.uk" not in result.sanitized_text
    assert "EMAIL" in result.redacted_types


@pytest.mark.parametrize(
    "card",
    [
        "4532-0151-1283-0366",  # Valid Visa (hyphenated)
        "4532 0151 1283 0366",  # Valid Visa (spaced)
        "4532015112830366",     # Valid Visa (raw 16 digits)
        "5425 2334 3010 9903",  # Valid MasterCard
    ],
)
def test_redacts_valid_credit_cards_without_ssn_collision(
    sanitizer: PresidioSanitizer, card: str
):
    result = sanitizer.sanitize(f"Please charge my card {card} today.")
    assert "<REDACTED: CREDIT_CARD>" in result.sanitized_text
    assert card not in result.sanitized_text
    assert "<REDACTED: SSN>" not in result.sanitized_text
    assert "CREDIT_CARD" in result.redacted_types


@pytest.mark.parametrize(
    "ssn",
    [
        "123-45-6789",
        "123 45 6789",
        "987654321",
    ],
)
def test_redacts_ssn_and_nine_numeric_digits(sanitizer: PresidioSanitizer, ssn: str):
    result = sanitizer.sanitize(f"El identificador es {ssn}.")
    assert "<REDACTED: SSN>" in result.sanitized_text
    assert ssn not in result.sanitized_text
    assert "SSN" in result.redacted_types


def test_redacts_mixed_pii_in_single_message(sanitizer: PresidioSanitizer):
    text = (
        "Hi, I am alice@example.com. My card is 4532-0151-1283-0366 "
        "and my SSN is 123-45-6789 (alt: 987654321)."
    )
    result = sanitizer.sanitize(text)

    assert "alice@example.com" not in result.sanitized_text
    assert "4532-0151-1283-0366" not in result.sanitized_text
    assert "123-45-6789" not in result.sanitized_text
    assert "987654321" not in result.sanitized_text

    assert "<REDACTED: EMAIL>" in result.sanitized_text
    assert "<REDACTED: CREDIT_CARD>" in result.sanitized_text
    assert result.sanitized_text.count("<REDACTED: SSN>") == 2
    assert result.redacted_types == ["CREDIT_CARD", "EMAIL", "SSN"]


def test_clean_message_unchanged(sanitizer: PresidioSanitizer):
    text = "Hello! What are your business hours on Monday?"
    result = sanitizer.sanitize(text)
    assert result.sanitized_text == text
    assert result.redactions_count == 0
    assert result.redacted_types == []


def test_fast_path_bypasses_presidio_on_clean_and_short_number_messages(
    sanitizer: PresidioSanitizer, monkeypatch: pytest.MonkeyPatch
):
    called = False

    def _fail_if_called(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("Presidio AnalyzerEngine should be bypassed by Fast-Path!")

    monkeypatch.setattr(sanitizer._analyzer, "analyze", _fail_if_called)

    clean = sanitizer.sanitize("General inquiry without emails or long numbers.")
    short_num = sanitizer.sanitize("Reference order #12345678 confirmed.")

    assert called is False
    assert clean.redactions_count == 0
    assert short_num.sanitized_text == "Reference order #12345678 confirmed."


def test_minimalist_registry_excludes_neural_spacy_recognizer(
    sanitizer: PresidioSanitizer,
):
    recognizer_names = {
        rec.name for rec in sanitizer._analyzer.registry.recognizers
    }
    assert "SpacyRecognizer" not in recognizer_names
    assert recognizer_names == {
        "CreditCardRecognizer",
        "EmailRecognizer",
        "UsSsnRecognizer",
        "GuardianNineDigitSSNRecognizer",
    }


def test_spacy_pipeline_removes_heavy_ner_and_parser_pipes(
    sanitizer: PresidioSanitizer,
):
    pipe_names = sanitizer._analyzer.nlp_engine.nlp["en"].pipe_names
    assert "ner" not in pipe_names
    assert "parser" not in pipe_names
