"""Wiring tests: does the gate actually sit in front of every send path?

The unit suite (test_allowlist.py) covers the decision function. A review showed
the gate could be deleted from all three senders in whatsapp.py while every test
stayed green — these tests exist to make that impossible.

Run from whatsapp-mcp-server/:
    python -m pytest test_send_paths.py -q
"""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import allowlist  # noqa: E402
import whatsapp  # noqa: E402

PERSON = "15550100001@s.whatsapp.net"


class FakeResponse:
    status_code = 200

    def json(self):
        return {"success": True, "message": "sent"}


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    cfg = tmp_path / "cfg"
    cfg.mkdir()
    monkeypatch.setenv("WHATSAPP_MCP_ALLOWLIST", str(cfg / "send-allowlist.json"))
    monkeypatch.setenv("WHATSAPP_MCP_AUDIT_LOG", str(cfg / "send-audit.jsonl"))
    for var in ("WHATSAPP_MCP_SEND_DISABLED", "WHATSAPP_MCP_SEND_DRY_RUN"):
        monkeypatch.delenv(var, raising=False)

    posts = []

    def fake_post(url, json=None, **kwargs):
        posts.append({"url": url, "payload": json})
        return FakeResponse()

    monkeypatch.setattr(whatsapp.requests, "post", fake_post)
    return {"cfg": cfg, "posts": posts}


def grant(cfg, caps=("text",), jid=PERSON):
    """Write an allowlist directly (avoids depending on the CLI under test)."""
    doc = {"version": 1, "entries": [
        {"jid": jid, "label": "Test", "allow": list(caps), "added": "2026-11-12T00:00:00Z"}
    ]}
    (cfg / "send-allowlist.json").write_text(json.dumps(doc), encoding="utf-8")


def media(tmp_path, name="doc.pdf", data=b"x"):
    p = tmp_path / name
    p.write_bytes(data)
    return str(p)


# --------------------------------------------------------------------------- #
# the gate must be consulted, and must block the HTTP call
# --------------------------------------------------------------------------- #

def test_text_refused_never_posts(isolated):
    """Empty allowlist -> refusal, and requests.post must not be called at all."""
    ok, msg = whatsapp.send_message(PERSON, "hello")
    assert ok is False
    assert msg.startswith("Refused:")
    assert isolated["posts"] == []


def test_file_refused_never_posts(isolated, tmp_path):
    ok, msg = whatsapp.send_file(PERSON, media(tmp_path))
    assert ok is False and msg.startswith("Refused:")
    assert isolated["posts"] == []


def test_audio_refused_never_posts(isolated, tmp_path):
    ok, msg = whatsapp.send_audio_message(PERSON, media(tmp_path, "v.ogg"))
    assert ok is False and msg.startswith("Refused:")
    assert isolated["posts"] == []


def test_unlisted_recipient_never_posts(isolated):
    grant(isolated["cfg"])
    ok, msg = whatsapp.send_message("15550199999@s.whatsapp.net", "hi")
    assert ok is False and "not on the send allowlist" in msg
    assert isolated["posts"] == []


def test_kill_switch_never_posts(isolated, monkeypatch):
    grant(isolated["cfg"])
    monkeypatch.setenv("WHATSAPP_MCP_SEND_DISABLED", "1")
    ok, _ = whatsapp.send_message(PERSON, "hi")
    assert ok is False
    assert isolated["posts"] == []


# --------------------------------------------------------------------------- #
# allowed paths reach the bridge with the right capability
# --------------------------------------------------------------------------- #

def test_text_allowed_posts_with_text_capability(isolated):
    grant(isolated["cfg"], ("text",))
    ok, _ = whatsapp.send_message(PERSON, "hello")
    assert ok is True
    assert len(isolated["posts"]) == 1
    payload = isolated["posts"][0]["payload"]
    assert payload["capability"] == "text"
    assert payload["recipient"] == PERSON
    assert "media_path" not in payload


def test_file_allowed_posts_with_file_capability(isolated, tmp_path):
    grant(isolated["cfg"], ("file",))
    ok, msg = whatsapp.send_file(PERSON, media(tmp_path, "doc.pdf"))
    assert ok is True, msg
    payload = isolated["posts"][0]["payload"]
    assert payload["capability"] == "file"
    assert payload["media_path"].endswith("doc.pdf")


def test_ogg_via_send_file_requires_audio_not_file(isolated, tmp_path):
    """A .ogg is delivered as a PTT voice note. Granting only 'file' must not
    authorise it — this was a real bypass through the agent's own tool surface."""
    grant(isolated["cfg"], ("file",))
    ok, msg = whatsapp.send_file(PERSON, media(tmp_path, "voice.ogg"))
    assert ok is False
    assert "not 'audio'" in msg
    assert isolated["posts"] == []


def test_ogg_via_send_file_allowed_with_audio_grant(isolated, tmp_path):
    grant(isolated["cfg"], ("audio",))
    ok, msg = whatsapp.send_file(PERSON, media(tmp_path, "voice.ogg"))
    assert ok is True, msg
    assert isolated["posts"][0]["payload"]["capability"] == "audio"


def test_audio_message_posts_audio_capability(isolated, tmp_path):
    grant(isolated["cfg"], ("audio",))
    ok, msg = whatsapp.send_audio_message(PERSON, media(tmp_path, "v.ogg"))
    assert ok is True, msg
    assert isolated["posts"][0]["payload"]["capability"] == "audio"


# --------------------------------------------------------------------------- #
# ordering: refuse before disclosing local filesystem state
# --------------------------------------------------------------------------- #

def test_refusal_happens_before_file_existence_check(isolated):
    """Without a grant the agent must not be able to probe paths: a missing file
    is already refused by the gate, so the error must be a refusal, not
    'Media file not found'."""
    ok, msg = whatsapp.send_file(PERSON, "/nonexistent/secret/id_rsa")
    assert ok is False
    assert msg.startswith("Refused:")
    assert "Media file not found" not in msg


def test_allowed_but_missing_file_reports_missing(isolated):
    grant(isolated["cfg"], ("file",))
    ok, msg = whatsapp.send_file(PERSON, "/nonexistent/x.pdf")
    assert ok is False
    assert "Media file not found" in msg
    assert isolated["posts"] == []
