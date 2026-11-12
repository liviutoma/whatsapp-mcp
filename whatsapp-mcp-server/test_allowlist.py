"""Tests for the fail-closed send allowlist.

Run from whatsapp-mcp-server/:
    python -m pytest test_allowlist.py -q
"""

import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import allowlist  # noqa: E402

PERSON = "15550100001@s.whatsapp.net"
GROUP = "120363000000000000@g.us"
LID = "100000000000001@lid"


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    """Every test gets its own allowlist + audit file and a clean env."""
    cfg = tmp_path / "cfg"
    cfg.mkdir()
    monkeypatch.setenv("WHATSAPP_MCP_ALLOWLIST", str(cfg / "send-allowlist.json"))
    monkeypatch.setenv("WHATSAPP_MCP_AUDIT_LOG", str(cfg / "send-audit.jsonl"))
    for var in ("WHATSAPP_MCP_SEND_DISABLED", "WHATSAPP_MCP_SEND_DRY_RUN"):
        monkeypatch.delenv(var, raising=False)
    return cfg


def write_allowlist(path: Path, entries, version=1):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"version": version, "entries": entries}), encoding="utf-8")


def allow(path: Path, jid: str, caps=("text",), **extra):
    entry = {"jid": jid, "label": extra.get("label", ""), "allow": list(caps),
             "added": extra.get("added", "2026-11-12T00:00:00+00:00")}
    write_allowlist(path, [entry])


# --------------------------------------------------------------------------- #
# normalisation
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("raw,expected", [
    ("15550100001@s.whatsapp.net", "15550100001@s.whatsapp.net"),
    ("+1 555 010 0002", "15550100002@s.whatsapp.net"),
    ("15550100002", "15550100002@s.whatsapp.net"),
    ("(555) 010-0002", "5550100002@s.whatsapp.net"),
    ("120363000000000000@g.us", "120363000000000000@g.us"),
    (LID, LID),
    ("15550100001:12@s.whatsapp.net", "15550100001@s.whatsapp.net"),
    ("15550100001@C.US", "15550100001@s.whatsapp.net"),
    ("15550100001@S.WHATSAPP.NET", "15550100001@s.whatsapp.net"),
])
def test_normalize_accepts(raw, expected):
    assert allowlist.normalize_jid(raw) == expected


@pytest.mark.parametrize("raw", ["", "   ", "status", "@s.whatsapp.net",
                                 "no-digits-here", "user@", "@"])
def test_normalize_rejects(raw):
    assert allowlist.normalize_jid(raw) is None


def test_device_suffix_cannot_dodge_entry(isolated):
    """A device-suffixed JID must match the plain entry, not bypass it."""
    path = isolated / "send-allowlist.json"
    allow(path, PERSON)
    assert allowlist.check_send("15550100001:7@s.whatsapp.net", "text").allowed


# --------------------------------------------------------------------------- #
# fail-closed: unusable allowlists
# --------------------------------------------------------------------------- #

def test_missing_file_refuses(isolated):
    d = allowlist.check_send(PERSON, "text")
    assert not d.allowed and d.code == "allowlist_unusable"
    assert "not found" in d.reason


def test_empty_file_refuses(isolated):
    (isolated / "send-allowlist.json").write_text("", encoding="utf-8")
    d = allowlist.check_send(PERSON, "text")
    assert not d.allowed and d.code == "allowlist_unusable"


def test_corrupt_json_refuses(isolated):
    (isolated / "send-allowlist.json").write_text("{not json", encoding="utf-8")
    d = allowlist.check_send(PERSON, "text")
    assert not d.allowed and d.code == "allowlist_unusable"
    assert "corrupt" in d.reason


def test_wrong_version_refuses(isolated):
    write_allowlist(isolated / "send-allowlist.json", [], version=99)
    d = allowlist.check_send(PERSON, "text")
    assert not d.allowed and d.code == "allowlist_unusable"


def test_empty_entries_refuses(isolated):
    write_allowlist(isolated / "send-allowlist.json", [])
    d = allowlist.check_send(PERSON, "text")
    assert not d.allowed and d.code == "not_allowlisted"


def test_entries_not_a_list_refuses(isolated):
    (isolated / "send-allowlist.json").write_text(
        json.dumps({"version": 1, "entries": {}}), encoding="utf-8")
    d = allowlist.check_send(PERSON, "text")
    assert not d.allowed and d.code == "allowlist_unusable"


def test_save_refuses_to_clobber_corrupt(isolated):
    path = isolated / "send-allowlist.json"
    path.write_text("garbage", encoding="utf-8")
    with pytest.raises(allowlist.AllowlistError):
        allowlist.save_allowlist({}, path)
    assert path.read_text(encoding="utf-8") == "garbage"


# --------------------------------------------------------------------------- #
# authorisation
# --------------------------------------------------------------------------- #

def test_allowed_text(isolated):
    allow(isolated / "send-allowlist.json", PERSON)
    d = allowlist.check_send(PERSON, "text")
    assert d.allowed and d.code == "allowed" and d.jid == PERSON


def test_allowed_via_bare_phone(isolated):
    allow(isolated / "send-allowlist.json", PERSON)
    assert allowlist.check_send("+1 555 010 0001", "text").allowed


def test_unlisted_recipient_refused(isolated):
    allow(isolated / "send-allowlist.json", PERSON)
    d = allowlist.check_send(GROUP, "text")
    assert not d.allowed and d.code == "not_allowlisted"
    assert "allowlist.py allow" in d.reason  # tells the human how to fix it


def test_capability_not_granted(isolated):
    allow(isolated / "send-allowlist.json", PERSON, caps=("text",))
    d = allowlist.check_send(PERSON, "file")
    assert not d.allowed and d.code == "capability_not_granted"
    assert "not 'file'" in d.reason


def test_capabilities_are_independent(isolated):
    allow(isolated / "send-allowlist.json", PERSON, caps=("text", "file", "audio"))
    for cap in ("text", "file", "audio"):
        assert allowlist.check_send(PERSON, cap).allowed


def test_group_can_be_allowed(isolated):
    allow(isolated / "send-allowlist.json", GROUP, caps=("text",))
    assert allowlist.check_send(GROUP, "text").allowed
    assert allowlist.jid_kind(GROUP) == "group"


def test_lid_can_be_allowed(isolated):
    allow(isolated / "send-allowlist.json", LID, caps=("text",))
    assert allowlist.check_send(LID, "text").allowed


def test_unknown_capability_in_entry_grants_nothing(isolated):
    path = isolated / "send-allowlist.json"
    write_allowlist(path, [{"jid": PERSON, "label": "x",
                            "allow": ["text", "bogus"], "added": ""}])
    assert allowlist.check_send(PERSON, "text").allowed
    assert not allowlist.check_send(PERSON, "bogus").allowed


def test_unknown_capability_request_refused(isolated):
    allow(isolated / "send-allowlist.json", PERSON)
    d = allowlist.check_send(PERSON, "admin")
    assert not d.allowed and d.code == "unknown_capability"


def test_duplicate_entries_narrow_not_widen(isolated):
    """Two entries for one JID must intersect to the empty set, not union."""
    path = isolated / "send-allowlist.json"
    write_allowlist(path, [
        {"jid": PERSON, "label": "a", "allow": ["text"], "added": ""},
        {"jid": PERSON, "label": "b", "allow": ["file"], "added": ""},
    ])
    entries = allowlist.load_allowlist(path)
    assert entries[PERSON].allow == ()
    assert not allowlist.check_send(PERSON, "text").allowed
    assert not allowlist.check_send(PERSON, "file").allowed


def test_duplicate_entries_intersection_keeps_common(isolated):
    path = isolated / "send-allowlist.json"
    write_allowlist(path, [
        {"jid": PERSON, "label": "a", "allow": ["text", "file"], "added": ""},
        {"jid": PERSON, "label": "b", "allow": ["text"], "added": ""},
    ])
    entries = allowlist.load_allowlist(path)
    assert entries[PERSON].allow == ("text",)


def test_bad_recipient(isolated):
    allow(isolated / "send-allowlist.json", PERSON)
    d = allowlist.check_send("not-a-recipient", "text")
    assert not d.allowed and d.code == "bad_recipient"


# --------------------------------------------------------------------------- #
# operator controls
# --------------------------------------------------------------------------- #

def test_kill_switch_overrides_allowlist(isolated, monkeypatch):
    allow(isolated / "send-allowlist.json", PERSON)
    monkeypatch.setenv("WHATSAPP_MCP_SEND_DISABLED", "1")
    d = allowlist.check_send(PERSON, "text")
    assert not d.allowed and d.code == "kill_switch"


@pytest.mark.parametrize("value", ["1", "true", "YES", "on"])
def test_kill_switch_value_spellings(isolated, monkeypatch, value):
    allow(isolated / "send-allowlist.json", PERSON)
    monkeypatch.setenv("WHATSAPP_MCP_SEND_DISABLED", value)
    assert not allowlist.check_send(PERSON, "text").allowed


@pytest.mark.parametrize("value", ["0", "false", "no", "", "off"])
def test_kill_switch_off_spellings(isolated, monkeypatch, value):
    allow(isolated / "send-allowlist.json", PERSON)
    monkeypatch.setenv("WHATSAPP_MCP_SEND_DISABLED", value)
    assert allowlist.check_send(PERSON, "text").allowed


def test_dry_run_never_allows(isolated, monkeypatch):
    allow(isolated / "send-allowlist.json", PERSON)
    monkeypatch.setenv("WHATSAPP_MCP_SEND_DRY_RUN", "1")
    d = allowlist.check_send(PERSON, "text")
    assert not d.allowed and d.code == "dry_run"
    assert "would send" in d.reason and PERSON in d.reason


def test_dry_run_reports_allowlist_problem_first(isolated, monkeypatch):
    """A dry run of an unlisted target should say unlisted, not 'dry run'."""
    monkeypatch.setenv("WHATSAPP_MCP_SEND_DRY_RUN", "1")
    d = allowlist.check_send(PERSON, "text")
    assert not d.allowed and d.code == "allowlist_unusable"


# --------------------------------------------------------------------------- #
# audit
# --------------------------------------------------------------------------- #

def test_audit_records_allowed_and_refused(isolated):
    allow(isolated / "send-allowlist.json", PERSON)
    allowlist.check_send(PERSON, "text")
    allowlist.check_send(GROUP, "text")

    log = isolated / "send-audit.jsonl"
    assert log.exists()
    rows = [json.loads(l) for l in log.read_text(encoding="utf-8").splitlines()]
    assert [r["allowed"] for r in rows] == [True, False]
    assert rows[0]["decision"] == "allowed"
    assert rows[1]["decision"] == "not_allowlisted"
    assert rows[1]["jid"] == GROUP


def test_audit_failure_does_not_block_send(isolated, monkeypatch):
    """Unwritable audit path must not change the decision."""
    allow(isolated / "send-allowlist.json", PERSON)
    monkeypatch.setenv("WHATSAPP_MCP_AUDIT_LOG", "/proc/nonexistent/audit.jsonl")
    assert allowlist.check_send(PERSON, "text").allowed


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def test_cli_allow_then_check_then_unallow(isolated, capsys):
    assert allowlist.main(["allow", PERSON, "--caps", "text,file", "--label", "Alice"]) == 0
    out = capsys.readouterr().out
    assert "resolved: " + PERSON in out
    assert "Alice" in out

    assert allowlist.main(["check", PERSON, "--capability", "file"]) == 0
    assert allowlist.main(["check", PERSON, "--capability", "audio"]) == 3

    assert allowlist.main(["unallow", PERSON]) == 0
    assert allowlist.main(["check", PERSON]) == 3


def test_cli_allow_bare_phone(isolated):
    assert allowlist.main(["allow", "+1 555 010 0001"]) == 0
    entries = allowlist.load_allowlist()
    assert PERSON in entries


def test_cli_rejects_unknown_caps(isolated):
    assert allowlist.main(["allow", PERSON, "--caps", "text,telepathy"]) == 1
    assert not (isolated / "send-allowlist.json").exists()


def test_cli_unallow_by_label(isolated):
    allowlist.main(["allow", PERSON, "--label", "Alice"])
    assert allowlist.main(["unallow", "alice"]) == 0
    assert allowlist.load_allowlist() == {}


def test_cli_list_refuses_corrupt(isolated, capsys):
    (isolated / "send-allowlist.json").write_text("{bad", encoding="utf-8")
    assert allowlist.main(["list"]) == 4
    assert "corrupt" in capsys.readouterr().err


def test_cli_default_caps_is_text_only(isolated):
    allowlist.main(["allow", PERSON])
    entries = allowlist.load_allowlist()
    assert entries[PERSON].allow == ("text",)


# --------------------------------------------------------------------------- #
# regression tests for defects found in review (2026-11-12)
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("bad_version", ["true", "1.0", "null", '"1"', "false"])
def test_non_integer_version_refused(isolated, bad_version):
    """`True == 1` and `1.0 == 1` in Python; only a real int 1 is acceptable."""
    (isolated / "send-allowlist.json").write_text(
        '{"version":%s,"entries":[]}' % bad_version, encoding="utf-8")
    d = allowlist.check_send(PERSON, "text")
    assert not d.allowed and d.code == "allowlist_unusable"


def test_non_utf8_allowlist_is_a_gate_error(isolated):
    """Must become AllowlistError, not escape as UnicodeDecodeError (which skipped
    the audit record and surfaced as 'Unexpected error')."""
    (isolated / "send-allowlist.json").write_bytes(b'{"version":1,"entries":[],"x":"\xff\xfe"}')
    d = allowlist.check_send(PERSON, "text")
    assert not d.allowed and d.code == "allowlist_unusable"
    assert "UTF-8" in d.reason


def test_tilde_user_path_is_literal_not_a_crash(isolated, monkeypatch):
    """Go treats any leading ~ as $HOME; Python's expanduser raises. Both now treat
    `~user` literally, so neither consults a file the other wouldn't."""
    monkeypatch.setenv("WHATSAPP_MCP_ALLOWLIST", "~nosuchuser/x.json")
    d = allowlist.check_send(PERSON, "text")
    assert not d.allowed and d.code == "allowlist_unusable"


@pytest.mark.parametrize("sep", ["\x1c", "\x1d", "\x1e", "\x1f"])
def test_kill_switch_not_spoofed_by_c0_separators(isolated, monkeypatch, sep):
    """str.strip() treats U+001C-001F as whitespace but Go's TrimSpace does not.
    Pinned to an ASCII-only trim set so both gates agree."""
    allow(isolated / "send-allowlist.json", PERSON)
    monkeypatch.setenv("WHATSAPP_MCP_SEND_DISABLED", sep + "1")
    # Not a recognised truthy spelling -> switch stays off, consistently.
    assert allowlist.check_send(PERSON, "text").allowed


def test_kill_switch_plain_value_still_works(isolated, monkeypatch):
    allow(isolated / "send-allowlist.json", PERSON)
    monkeypatch.setenv("WHATSAPP_MCP_SEND_DISABLED", " 1 ")
    assert allowlist.check_send(PERSON, "text").code == "kill_switch"


@pytest.mark.parametrize("recipient", [
    "\u0664\u0669\u0661\u0665", "\uff14\uff19\uff11\uff15", "4915\u0666\u0663",
])
def test_non_ascii_digits_are_not_digits(isolated, recipient):
    """Go filters ASCII digits only; Python's str.isdigit() accepts unicode digits,
    which let Go widen a grant (e.g. '4915' + Arabic digits matched '4915')."""
    allow(isolated / "send-allowlist.json", "4915@s.whatsapp.net")
    d = allowlist.check_send(recipient, "text")
    assert not d.allowed
    assert d.code in {"bad_recipient", "not_allowlisted"}


def test_load_level_capability_filter(isolated):
    """Assert the FILTER result, not just that a bogus request is refused — the
    request-side check masked this and a broken filter went unnoticed."""
    path = isolated / "send-allowlist.json"
    write_allowlist(path, [{"jid": PERSON, "label": "x",
                            "allow": ["text", "bogus", "TEXT"], "added": ""}])
    assert allowlist.load_allowlist(path)[PERSON].allow == ("text",)


def test_decision_is_falsy_when_refused():
    """whatsapp.py branches on the decision; if __bool__ regressed to True every
    refusal would become a send."""
    assert not allowlist.Decision(False, "not_allowlisted", "no")
    assert allowlist.Decision(True, "allowed", "yes")


def test_audit_log_is_private_and_labelled(isolated):
    allow(isolated / "send-allowlist.json", PERSON)
    allowlist.check_send(PERSON, "text", media_path="/tmp/x.pdf")

    log = isolated / "send-audit.jsonl"
    assert oct(log.stat().st_mode)[-3:] == "600"
    assert oct((isolated).stat().st_mode)[-3:] in {"700", "755"}  # tmp_path itself
    row = json.loads(log.read_text(encoding="utf-8").splitlines()[0])
    assert row["source"] == "mcp"
    assert row["capability"] == "text"
    assert row["media_path"] == "/tmp/x.pdf"
    assert row["requested"] == PERSON


def test_audit_dir_is_private(isolated, tmp_path, monkeypatch):
    monkeypatch.setenv("WHATSAPP_MCP_AUDIT_LOG", str(tmp_path / "fresh" / "a.jsonl"))
    allow(isolated / "send-allowlist.json", PERSON)
    allowlist.check_send(PERSON, "text")
    assert oct((tmp_path / "fresh").stat().st_mode)[-3:] == "700"


def test_media_capability_derivation():
    assert allowlist.media_capability("") == "text"
    assert allowlist.media_capability("/tmp/voice.ogg") == "audio"
    assert allowlist.media_capability("/tmp/VOICE.OGG") == "audio"
    assert allowlist.media_capability("/tmp/song.mp3") == "file"
    assert allowlist.media_capability("/tmp/doc.pdf") == "file"
    assert allowlist.media_capability("/tmp/noext") == "file"


def test_mutate_allowlist_does_not_resurrect_revoked_entry(isolated):
    """Locked read-modify-write: a grant applied over a revocation must not restore
    the revoked entry from a stale snapshot."""
    path = isolated / "send-allowlist.json"
    allow(path, PERSON)
    allowlist.mutate_allowlist(lambda e: e.pop(PERSON), path)
    assert allowlist.load_allowlist(path) == {}
    allowlist.mutate_allowlist(
        lambda e: e.__setitem__("4917000000000@s.whatsapp.net",
                                allowlist.Entry(jid="4917000000000@s.whatsapp.net",
                                                allow=("text",))), path)
    assert PERSON not in allowlist.load_allowlist(path)


def test_allowlist_cannot_be_sent_as_media(isolated):
    """The gate's own state is not sendable: exfiltrating the allowlist would hand
    over the policy and every recipient it protects."""
    allow(isolated / "send-allowlist.json", PERSON, caps=("file",))
    for target in (isolated / "send-allowlist.json", isolated):
        d = allowlist.check_send(PERSON, "file", media_path=str(target))
        assert not d.allowed and d.code == "sensitive_media_path", d


def test_sensitive_path_check_does_not_block_normal_files(isolated):
    allow(isolated / "send-allowlist.json", PERSON, caps=("file",))
    d = allowlist.check_send(PERSON, "file", media_path="/tmp/report.pdf")
    assert d.allowed
