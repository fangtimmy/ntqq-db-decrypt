from __future__ import annotations

import json
import unittest

from qqdb import proto, schema


def varint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def int_field(number: int, value: int) -> bytes:
    return varint(number << 3) + varint(value)


def bytes_field(number: int, value: bytes) -> bytes:
    return varint((number << 3) | 2) + varint(len(value)) + value


def element(*fields: bytes) -> bytes:
    return bytes_field(schema.CONTENT_FIELD, b"".join(fields))


def text_element(value: str) -> bytes:
    return element(
        int_field(schema.ELEMENT_TYPE, schema.ELEMENT_TEXT),
        bytes_field(schema.TEXT, value.encode()),
    )


class ProtoTests(unittest.TestCase):
    def test_text(self) -> None:
        elements = proto.message_elements(text_element("hello"))
        self.assertEqual(len(elements), 1)
        self.assertEqual(elements[0].type, "text")
        self.assertEqual(elements[0].summary, "hello")

    def test_multiple_elements(self) -> None:
        blob = text_element("one") + text_element("two")
        elements = proto.message_elements(blob)
        self.assertEqual([item.summary for item in elements], ["one", "two"])

    def test_image(self) -> None:
        blob = element(
            int_field(schema.ELEMENT_TYPE, schema.ELEMENT_IMAGE),
            bytes_field(schema.FILE_NAME, b"photo.png"),
            int_field(schema.FILE_SIZE, 1234),
            int_field(schema.WIDTH, 640),
            int_field(schema.HEIGHT, 480),
            bytes_field(schema.IMAGE_MD5, b"0123456789abcdef0123456789abcdef"),
            bytes_field(schema.IMAGE_TOKEN, b"token"),
            bytes_field(schema.IMAGE_URL, b"/download?fileid=abc"),
            bytes_field(schema.IMAGE_HOST, b"multimedia.nt.qq.com.cn"),
        )
        result = proto.message_elements(blob)[0]
        self.assertEqual(result.type, "image")
        self.assertEqual(result.data["file_name"], "photo.png")
        self.assertEqual(result.data["width"], 640)
        self.assertEqual(
            result.data["urls"], ["https://multimedia.nt.qq.com.cn/download?fileid=abc"]
        )
        self.assertIn("photo.png", result.summary)

    def test_file_strips_ntos_prefix(self) -> None:
        blob = element(
            int_field(schema.ELEMENT_TYPE, schema.ELEMENT_FILE),
            bytes_field(schema.FILE_NAME, b"report.docx"),
            bytes_field(schema.FILE_PATH, b"::NTOSFull::/tmp/report.docx"),
            int_field(schema.FILE_SIZE, 2048),
            bytes_field(schema.FILE_ID, b"/file-id"),
        )
        result = proto.message_elements(blob)[0]
        self.assertEqual(result.type, "file")
        self.assertEqual(result.data["local_path"], "/tmp/report.docx")
        self.assertEqual(result.data["file_id"], "/file-id")

    def test_face(self) -> None:
        blob = element(
            int_field(schema.ELEMENT_TYPE, schema.ELEMENT_FACE),
            int_field(schema.FACE_ID, 74),
            bytes_field(schema.FACE_NAME, "/吃糖".encode()),
        )
        result = proto.message_elements(blob)[0]
        self.assertEqual(result.type, "face")
        self.assertEqual(result.summary, "[表情] /吃糖")

    def test_ark_json(self) -> None:
        payload = json.dumps(
            {"meta": {"news": {"title": "Title", "desc": "Desc", "url": "https://x"}}}
        ).encode()
        blob = element(
            int_field(schema.ELEMENT_TYPE, schema.ELEMENT_ARK),
            bytes_field(schema.ARK_JSON, payload),
        )
        result = proto.message_elements(blob)[0]
        self.assertEqual(result.type, "ark")
        self.assertEqual(result.data["title"], "Title")
        self.assertEqual(result.data["url"], "https://x")

    def test_multi_msg(self) -> None:
        xml = b'<msg brief="[chat]" tSum="3" m_fileName="abc"></msg>'
        blob = element(
            int_field(schema.ELEMENT_TYPE, schema.ELEMENT_MULTI_MSG),
            bytes_field(schema.MULTI_MSG_XML, xml),
            bytes_field(schema.MULTI_MSG_ID, b"abc"),
        )
        result = proto.message_elements(blob)[0]
        self.assertEqual(result.type, "multi_msg")
        self.assertEqual(result.data["brief"], "[chat]")
        self.assertEqual(result.data["count"], 3)

    def test_unknown_type(self) -> None:
        blob = element(
            int_field(schema.ELEMENT_TYPE, 99),
            int_field(9999, 7),
        )
        result = proto.message_elements(blob)[0]
        self.assertEqual(result.type, "unknown")
        self.assertEqual(result.data["element_type"], 99)

    def test_empty(self) -> None:
        self.assertEqual(proto.message_elements(None), [])
        self.assertEqual(proto.message_elements(b""), [])


if __name__ == "__main__":
    unittest.main()
