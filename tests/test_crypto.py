import base64
import os
import pytest

from app.crypto import EncryptionError, MessageEncryptor


def _random_key() -> str:
    return base64.urlsafe_b64encode(os.urandom(32)).decode("ascii")


def test_encrypt_decrypt_roundtrip():
    encryptor = MessageEncryptor(_random_key())
    secret = "My SSN is 123-45-6789 and email is alice@example.com"

    token = encryptor.encrypt(secret)
    assert token != secret
    assert "123-45-6789" not in token
    assert encryptor.decrypt(token) == secret


def test_unique_nonce_produces_different_ciphertexts():
    encryptor = MessageEncryptor(_random_key())
    message = "Identical sensitive payload"

    token_1 = encryptor.encrypt(message)
    token_2 = encryptor.encrypt(message)

    assert token_1 != token_2
    assert encryptor.decrypt(token_1) == message
    assert encryptor.decrypt(token_2) == message


def test_tampered_ciphertext_fails_authentication():
    encryptor = MessageEncryptor(_random_key())
    token = encryptor.encrypt("Confidential message")

    raw = bytearray(base64.urlsafe_b64decode(token.encode("ascii")))
    raw[-1] ^= 0xFF  # Flip bits in authentication tag
    tampered = base64.urlsafe_b64encode(bytes(raw)).decode("ascii")

    with pytest.raises(EncryptionError):
        encryptor.decrypt(tampered)


def test_wrong_key_fails_decryption():
    enc_a = MessageEncryptor(_random_key())
    enc_b = MessageEncryptor(_random_key())

    token = enc_a.encrypt("Secret")
    with pytest.raises(EncryptionError):
        enc_b.decrypt(token)


def test_invalid_key_length_rejected():
    short_key = base64.urlsafe_b64encode(b"too-short").decode("ascii")
    with pytest.raises(EncryptionError):
        MessageEncryptor(short_key)
