from __future__ import annotations

import unittest
from datetime import datetime

from qqdb import proto, schema
from qqdb.model import Directory, Message, filter_conversations, parse_message_row
from tests.test_proto import bytes_field, element, int_field, text_element


class ModelTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = Directory(
            self_uid="u_self",
            self_uin=10001,
            self_name="Me",
            nicknames={"u_alice": "Alice"},
            groups={"123456": "Test Group"},
            group_members={("123456", "u_alice"): "Alice Card"},
        )

    def test_group_message(self) -> None:
        row = {
            schema.CHAT_TYPE: 2,
            schema.MSG_TYPE: 2,
            schema.MSG_SUB_TYPE: 1,
            schema.SENDER_UID: "u_alice",
            schema.CHAT_UID: "123456",
            schema.CHAT_UIN: 123456,
            schema.SENDER_UIN: 20002,
            schema.DIRECTION: 0,
            schema.SENDER_FLAG: 0,
            schema.MSG_TIME: 1700000000,
            schema.SENDER_NAME: "Alice Card",
            schema.CONTENT: text_element("hello"),
            schema.MSG_ID: 42,
            schema.MSG_SEQ: 7,
        }
        message = parse_message_row(row, self.directory)
        self.assertIsNotNone(message)
        assert message is not None
        self.assertEqual(message.chat_type, "group")
        self.assertEqual(message.chat_id, "123456")
        self.assertEqual(message.chat_name, "Test Group")
        self.assertEqual(message.sender_name, "Alice Card")
        self.assertFalse(message.outgoing)
        self.assertEqual(message.text, "hello")
        self.assertEqual(
            message.to_dict()["time"],
            datetime.fromtimestamp(1700000000).strftime("%Y-%m-%d %H:%M:%S"),
        )

    def test_outgoing_message(self) -> None:
        row = {
            schema.CHAT_TYPE: 2,
            schema.MSG_TYPE: 2,
            schema.SENDER_UID: "u_self",
            schema.CHAT_UID: "123456",
            schema.DIRECTION: 0,
            schema.MSG_TIME: 1700000001,
            schema.CONTENT: text_element("mine"),
            schema.MSG_ID: 43,
        }
        message = parse_message_row(row, self.directory)
        assert message is not None
        self.assertTrue(message.outgoing)
        self.assertEqual(message.sender_name, "Me")

    def test_system_message_without_content(self) -> None:
        row = {
            schema.CHAT_TYPE: 2,
            schema.MSG_TYPE: schema.MESSAGE_SYSTEM,
            schema.CHAT_UID: "123456",
            schema.SENDER_UID: "123456",
            schema.MSG_TIME: 1700000002,
            schema.MSG_ID: 44,
        }
        message = parse_message_row(row, self.directory)
        assert message is not None
        self.assertEqual(message.text, "[系统消息]")
        self.assertEqual(message.elements, [])

    def test_filter_conversations(self) -> None:
        from qqdb.model import Conversation

        conversations = [
            Conversation("group", "123456", "Test Group"),
            Conversation("c2c", "u_alice", "Alice"),
        ]
        self.assertEqual(len(filter_conversations(conversations, "test")), 1)
        self.assertEqual(len(filter_conversations(conversations, "u_alice")), 1)
        self.assertEqual(len(filter_conversations(conversations, "zzz")), 0)


if __name__ == "__main__":
    unittest.main()
