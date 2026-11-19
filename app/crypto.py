import base64
import binascii
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_SIZE_BYTES = 12  # Standard 96-bit nonce for AES-GCM
KEY_SIZE_BYTES = 32    # 256-bit key for AES-256-GCM


class EncryptionError(ValueError):
    """Raised when encryption configuration or decryption fails."""


class MessageEncryptor:
    """AES-256-GCM authenticated encryptor for sensitive audit log payloads."""

    def __init__(self, base64_key: str) -> None:
        try:
            key_bytes = base64.urlsafe_b64decode(base64_key.encode("utf-8"))
        except (binascii.Error, ValueError) as exc:
            raise EncryptionError("ENCRYPTION_KEY must be valid Base64.") from exc

        if len(key_bytes) != KEY_SIZE_BYTES:
            raise EncryptionError(
                f"ENCRYPTION_KEY must decode to exactly {KEY_SIZE_BYTES} bytes "
                f"(got {len(key_bytes)} bytes)."
            )

        self._aesgcm = AESGCM(key_bytes)

    def encrypt(self, plaintext: str) -> str:
        """Encrypt UTF-8 plaintext with a fresh random 96-bit nonce."""
        nonce = os.urandom(NONCE_SIZE_BYTES)
        ciphertext = self._aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
        return base64.urlsafe_b64encode(nonce + ciphertext).decode("ascii")

    def decrypt(self, token: str) -> str:
        """Decrypt and authenticate a Base64-encoded AES-256-GCM token."""
        try:
            raw = base64.urlsafe_b64decode(token.encode("ascii"))
        except (binascii.Error, ValueError) as exc:
            raise EncryptionError("Invalid Base64 ciphertext token.") from exc

        if len(raw) <= NONCE_SIZE_BYTES:
            raise EncryptionError("Ciphertext token is too short.")

        nonce, ciphertext = raw[:NONCE_SIZE_BYTES], raw[NONCE_SIZE_BYTES:]
        try:
            plaintext_bytes = self._aesgcm.decrypt(nonce, ciphertext, None)
        except Exception as exc:
            raise EncryptionError(
                "Decryption failed: invalid key or tampered ciphertext."
            ) from exc

        return plaintext_bytes.decode("utf-8")
