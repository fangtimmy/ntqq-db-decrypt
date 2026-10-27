from __future__ import annotations

import csv
import json
import tempfile
import unittest
from pathlib import Path

from qqdb.export import export_conversations
from qqdb.model import Conversation, Message
from qqdb.proto import Element


def make_message(msg_id: int, text: str, outgoing: bool = False) -> Message:
    return Message(
        msg_id=msg_id,
        seq=msg_id,
        timestamp=1700000000 + msg_id,
        chat_type="group",
        chat_id="123456",
        chat_name="Test Group",
        sender_uid="u_self" if outgoing else "u_alice",
        sender_uin=10001 if outgoing else 20002,
        sender_name="Me" if outgoing else "Alice",
        outgoing=outgoing,
        msg_type=2,
        sub_type=1,
        elements=[Element("text", {"text": text})],
    )


class ExportTests(unittest.TestCase):
    def test_export_all_formats(self) -> None:
        conversation = Conversation(
            "group",
            "123456",
            "Test Group",
            [make_message(1, "hello"), make_message(2, "mine", outgoing=True)],
        )
        with tempfile.TemporaryDirectory() as temp:
            result = export_conversations([conversation], temp)
            out = Path(temp)
            self.assertEqual(result["conversations"], 1)
            self.assertEqual(result["messages"], 2)
            self.assertTrue((out / "index.csv").exists())
            chat_dir = next((out / "chats").iterdir())
            for name in ("chat.txt", "chat.csv", "chat.json", "chat.jsonl"):
                self.assertTrue((chat_dir / name).exists(), name)

            with (out / "index.csv").open(encoding="utf-8") as handle:
                index_rows = list(csv.DictReader(handle))
            self.assertEqual(index_rows[0]["chat_name"], "Test Group")
            self.assertEqual(index_rows[0]["message_count"], "2")

            payload = json.loads((chat_dir / "chat.json").read_text(encoding="utf-8"))
            self.assertEqual(payload[0]["text"], "hello")
            self.assertTrue(payload[1]["outgoing"])
            self.assertEqual(payload[1]["elements"][0]["type"], "text")

            text = (chat_dir / "chat.txt").read_text(encoding="utf-8")
            self.assertIn("Alice: hello", text)

    def test_refuses_non_empty_directory(self) -> None:
        conversation = Conversation("group", "1", "G", [make_message(1, "x")])
        with tempfile.TemporaryDirectory() as temp:
            Path(temp, "keep.txt").write_text("x", encoding="utf-8")
            with self.assertRaises(FileExistsError):
                export_conversations([conversation], temp)

    def test_unknown_format(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(ValueError):
                export_conversations([], temp, formats="txt,doc")


if __name__ == "__main__":
    unittest.main()
