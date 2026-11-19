import asyncio
import json
import os
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from app.crypto import MessageEncryptor


class AuditLogger:
    """Async-safe, atomic JSON audit store for encrypted original + redacted messages."""

    def __init__(self, file_path: str, encryptor: MessageEncryptor) -> None:
        self.file_path = Path(file_path)
        self._encryptor = encryptor
        self._lock = asyncio.Lock()

    def _read_records_sync(self) -> List[Dict[str, Any]]:
        if not self.file_path.exists():
            return []
        content = self.file_path.read_text(encoding="utf-8").strip()
        if not content:
            return []
        data = json.loads(content)
        if not isinstance(data, list):
            return []
        return data

    def _write_records_atomic_sync(self, records: List[Dict[str, Any]]) -> None:
        self.file_path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(
            dir=str(self.file_path.parent),
            prefix=".audit_log_",
            suffix=".tmp",
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as tmp_file:
                json.dump(records, tmp_file, indent=2, ensure_ascii=False)
                tmp_file.flush()
                os.fsync(tmp_file.fileno())
            os.replace(tmp_path, self.file_path)
        except Exception:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
            raise

    async def record(
        self,
        *,
        user_id: str,
        original_message: str,
        redacted_message: str,
        redacted_types: List[str],
        outcome: str,
    ) -> Dict[str, Any]:
        """Encrypt the original message and atomically append an audit entry."""
        entry: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "userId": user_id,
            "originalMessageEncrypted": self._encryptor.encrypt(original_message),
            "redactedMessage": redacted_message,
            "redactedTypes": redacted_types,
            "outcome": outcome,
        }

        async with self._lock:
            records = await asyncio.to_thread(self._read_records_sync)
            records.append(entry)
            await asyncio.to_thread(self._write_records_atomic_sync, records)

        return entry
