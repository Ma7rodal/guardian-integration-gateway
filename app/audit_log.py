import asyncio
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from app.crypto import MessageEncryptor


class AuditLogger:
    """Async-safe O(1) append-only JSON Lines (.jsonl) audit store.

    Stores each inquiry as one self-contained JSON line containing the
    AES-256-GCM encrypted original message and plaintext redacted message,
    avoiding O(n) full-file reads/rewrites under sustained traffic.
    """

    def __init__(self, file_path: str, encryptor: MessageEncryptor) -> None:
        self.file_path = Path(file_path)
        self._encryptor = encryptor
        self._lock = asyncio.Lock()

    def _append_line_sync(self, entry: Dict[str, Any]) -> None:
        self.file_path.parent.mkdir(parents=True, exist_ok=True)
        serialized = json.dumps(entry, ensure_ascii=False) + "\n"
        with self.file_path.open("a", encoding="utf-8") as audit_file:
            audit_file.write(serialized)
            audit_file.flush()
            os.fsync(audit_file.fileno())

    @staticmethod
    def read_records(file_path: Path) -> List[Dict[str, Any]]:
        """Parse all JSONL audit records from disk."""
        if not file_path.exists():
            return []
        records: List[Dict[str, Any]] = []
        with file_path.open("r", encoding="utf-8") as audit_file:
            for line in audit_file:
                stripped = line.strip()
                if stripped:
                    records.append(json.loads(stripped))
        return records

    async def record(
        self,
        *,
        user_id: str,
        original_message: str,
        redacted_message: str,
        redacted_types: List[str],
        outcome: str,
    ) -> Dict[str, Any]:
        """Encrypt the original message and append an O(1) JSONL audit entry."""
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
            await asyncio.to_thread(self._append_line_sync, entry)

        return entry
