"""Fail-closed send allowlist for the WhatsApp MCP server.

Every outbound WhatsApp action must pass through :func:`check_send` before the
bridge is contacted.  The model of safety is deliberately pessimistic:

* Nothing is allowed by default.  A missing, empty, unreadable or unparseable
  allowlist refuses **every** send.
* Authorisation is keyed on the exact WhatsApp JID, never on a display name.
  Names are attacker-controlled (anyone can rename themselves to "Alice") and
  collide, so a label can never authorise a send; a label is decoration only.
* Grants are per capability (``text``/``file``/``audio``) so a contact can be
  reachable by text while remaining unreachable by attachments.

Management is a small CLI (``python allowlist.py ...``) — see ``--help``.
"""

from __future__ import annotations

import json
import os
import sqlite3
import sys
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

try:  # POSIX advisory locking for read-modify-write; absent on Windows.
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None  # type: ignore[assignment]

ALLOWLIST_VERSION = 1
CAPABILITIES: Tuple[str, ...] = ("text", "file", "audio")

#: WhatsApp JID servers we know how to reason about.  Anything else is still
#: allowed to be *listed*, but never inferred from a bare number.
PERSON_SERVER = "s.whatsapp.net"

DEFAULT_CONFIG_DIR = Path.home() / ".config" / "whatsapp-mcp"
DEFAULT_ALLOWLIST_PATH = DEFAULT_CONFIG_DIR / "send-allowlist.json"
DEFAULT_AUDIT_PATH = DEFAULT_CONFIG_DIR / "send-audit.jsonl"

_MSG_DB_PATH = Path(__file__).resolve().parent.parent / "whatsapp-bridge" / "store" / "messages.db"


# --------------------------------------------------------------------------- #
# paths / environment
# --------------------------------------------------------------------------- #

def _expand(path_str: str) -> Path:
    """Expand a leading ``~`` / ``~/`` only.

    Deliberately mirrors the Go gate's rule rather than using ``Path.expanduser``:
    that raises ``RuntimeError`` on ``~unknownuser``, which would escape the gate's
    error contract, and Go treats any leading ``~`` as ``$HOME`` — so the two would
    have consulted different files. ``~user`` is left literal in both.
    """
    if path_str == "~":
        return Path.home()
    if path_str.startswith("~/"):
        return Path.home() / path_str[2:]
    return Path(path_str)


def allowlist_path() -> Path:
    """Allowlist location, honouring ``WHATSAPP_MCP_ALLOWLIST``."""
    override = os.environ.get("WHATSAPP_MCP_ALLOWLIST", "").strip(" \t\r\n")
    return _expand(override) if override else DEFAULT_ALLOWLIST_PATH


def audit_path() -> Path:
    """Audit log location, honouring ``WHATSAPP_MCP_AUDIT_LOG``."""
    override = os.environ.get("WHATSAPP_MCP_AUDIT_LOG", "").strip(" \t\r\n")
    return _expand(override) if override else DEFAULT_AUDIT_PATH


#: Env-flag truthiness is pinned to an ASCII-only trim set. ``str.strip()`` with no
#: arguments also strips U+001C–U+001F, which would let
#: ``WHATSAPP_MCP_SEND_DISABLED=$'\x1c1'`` read as ON in Python but OFF in Go — a
#: kill switch that disagrees with itself. Both gates use exactly this set.
_ASCII_WS = " \t\r\n"


def _truthy_env(name: str) -> bool:
    return os.environ.get(name, "").strip(_ASCII_WS).lower() in {"1", "true", "yes", "on"}


def send_disabled() -> bool:
    """Global kill switch: ``WHATSAPP_MCP_SEND_DISABLED=1`` refuses everything.

    Per-process, not machine-wide: the MCP server and the bridge read their own
    environments. Set it for both if you want both stopped.
    """
    return _truthy_env("WHATSAPP_MCP_SEND_DISABLED")


def dry_run_enabled() -> bool:
    """``WHATSAPP_MCP_SEND_DRY_RUN=1`` resolves and reports but never sends."""
    return _truthy_env("WHATSAPP_MCP_SEND_DRY_RUN")


# --------------------------------------------------------------------------- #
# recipient normalisation
# --------------------------------------------------------------------------- #

#: Characters permitted in a bare phone number: digits plus the usual human
#: formatting. Anything else (letters, unicode digits, symbols) is rejected rather
#: than filtered — filtering is what let `"4915" + Arabic-Indic digits` normalise
#: to an allowlisted `4915@s.whatsapp.net` while being a different string.
_BARE_ALLOWED = frozenset("0123456789+-() ")
_USER_ALLOWED = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")
_SERVER_ALLOWED = frozenset("abcdefghijklmnopqrstuvwxyz0123456789.-")


def normalize_jid(recipient: str) -> Optional[str]:
    """Normalise a recipient into a canonical ``user@server`` JID.

    Accepts a full JID (``4917...@s.whatsapp.net``, ``120363...@g.us``,
    ``...@lid``, ``...@newsletter``) or a bare phone number in any human
    formatting (``+1 555 010 0002``).  Returns ``None`` when the input cannot be
    understood, which the gate treats as a refusal.

    » ``@c.us`` is legacy for ``@s.whatsapp.net`` and is folded in, so the same
    phone resolved from an old record and a new one matches one entry.
    » Character sets are validated, never filtered. Filtering silently rewrote an
    input into a *different* (allowlisted) identity.
    """
    if not recipient or not isinstance(recipient, str):
        return None
    raw = recipient.strip(" \t\r\n")
    if not raw:
        return None

    if "@" in raw:
        user, _, server = raw.partition("@")
        user = user.strip(" \t\r\n")
        server = server.strip(" \t\r\n").lower()
        if not user or not server:
            return None
        # A second '@' makes the JID ambiguous to whatsmeow (it keeps only the
        # first two parts), so the gate and the sender could disagree.
        if "@" in server or "@" in user:
            return None
        if server == "c.us":
            server = PERSON_SERVER
        if not set(server) <= _SERVER_ALLOWED:
            return None
        # A device suffix ("4917...:12@s.whatsapp.net") addresses one linked
        # device of a user; strip it so it cannot dodge an allowlist entry.
        user = user.split(":", 1)[0].strip(" \t\r\n")
        if not user or not set(user) <= _USER_ALLOWED:
            return None
        return f"{user}@{server}"

    if not set(raw) <= _BARE_ALLOWED:
        return None
    digits = "".join(ch for ch in raw if ch in "0123456789")
    if not digits:
        return None
    return f"{digits}@{PERSON_SERVER}"


#: Extensions the bridge turns into a WhatsApp audio (PTT) message. Only ``.ogg``
#: does so today (``main.go`` maps ``ogg`` → ``MediaAudio`` + ``PTT:true``); every
#: other extension becomes an image, video, or document. This set is therefore the
#: single definition of what "audio" means, shared with the Go gate.
AUDIO_EXTENSIONS: Tuple[str, ...] = ("ogg",)


def media_capability(media_path: str) -> str:
    """Which capability a payload actually exercises — derived, never asserted.

    ``text`` for a body with no media, ``audio`` when the bridge would deliver a
    voice note, ``file`` for everything else. Callers must use this rather than
    naming a capability themselves, so a ``text`` grant cannot carry a file and a
    ``file`` grant cannot carry a voice note.
    """
    if not media_path:
        return "text"
    ext = media_path.rsplit(".", 1)[-1].lower() if "." in media_path else ""
    return "audio" if ext in AUDIO_EXTENSIONS else "file"


def _server_of(jid: str) -> str:
    return jid.partition("@")[2]


def jid_kind(jid: str) -> str:
    """Human label for the sort of JID this is."""
    server = _server_of(jid)
    return {
        "s.whatsapp.net": "person",
        "g.us": "group",
        "lid": "person (privacy id)",
        "newsletter": "channel",
        "broadcast": "broadcast list",
    }.get(server, server or "unknown")


# --------------------------------------------------------------------------- #
# allowlist file
# --------------------------------------------------------------------------- #

class AllowlistError(Exception):
    """The allowlist file is missing or unusable — sends must be refused."""

    def __init__(self, reason: str, path: Optional[Path] = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.path = path


@dataclass
class Entry:
    jid: str
    allow: Tuple[str, ...]
    label: str = ""
    added: str = ""

    def to_json(self) -> Dict[str, Any]:
        return {"jid": self.jid, "label": self.label,
                "allow": list(self.allow), "added": self.added}


def _now() -> str:
    """RFC3339 UTC with a ``Z`` suffix — same shape the Go gate writes."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_allowlist(path: Optional[Path] = None) -> Dict[str, Entry]:
    """Read and validate the allowlist.  Raises :class:`AllowlistError`.

    Never repairs or rewrites the file — a corrupt allowlist must be fixed by a
    human, not silently replaced by a permissive default.
    """
    path = path or allowlist_path()
    if not path.exists():
        raise AllowlistError(f"allowlist file not found at {path}", path)

    try:
        raw_bytes = path.read_bytes()
    except OSError as exc:
        raise AllowlistError(f"allowlist unreadable ({exc})", path) from exc

    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        # Decoded explicitly so a mangled file becomes the gate's own error rather
        # than a stray UnicodeDecodeError escaping check_send and skipping the
        # audit record.
        raise AllowlistError(f"allowlist is not valid UTF-8 ({exc})", path) from exc

    if not text.strip():
        raise AllowlistError(f"allowlist is empty at {path}", path)

    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        raise AllowlistError(f"allowlist is corrupt (invalid JSON: {exc})", path) from exc

    if not isinstance(doc, dict):
        raise AllowlistError("allowlist is corrupt (top level must be an object)", path)

    version = doc.get("version")
    # `True == 1` and `1.0 == 1` in Python, so a plain comparison would accept
    # `{"version": true}` — which the Go gate rejects. Require a real int.
    if isinstance(version, bool) or not isinstance(version, int) or version != ALLOWLIST_VERSION:
        raise AllowlistError(
            f"allowlist has unsupported version {version!r} (expected {ALLOWLIST_VERSION})",
            path,
        )

    raw_entries = doc.get("entries")
    if not isinstance(raw_entries, list):
        raise AllowlistError("allowlist is corrupt (entries must be a list)", path)

    entries: Dict[str, Entry] = {}
    for item in raw_entries:
        if not isinstance(item, dict):
            raise AllowlistError("allowlist is corrupt (entry must be an object)", path)
        jid = normalize_jid(item.get("jid", ""))
        if not jid:
            raise AllowlistError(
                f"allowlist contains an entry with an invalid jid: {item.get('jid')!r}", path
            )
        granted = item.get("allow")
        if not isinstance(granted, list):
            raise AllowlistError(f"allowlist entry {jid} is missing an 'allow' list", path)
        # Unknown capability names grant nothing (fail closed, not open).
        caps = tuple(sorted({c for c in granted if isinstance(c, str) and c in CAPABILITIES}))
        label = item.get("label") if isinstance(item.get("label"), str) else ""
        added = item.get("added") if isinstance(item.get("added"), str) else ""

        if jid in entries:
            # Duplicates narrow rather than widen: intersection, never union.
            existing = entries[jid]
            caps = tuple(sorted(set(existing.allow) & set(caps)))
            label = existing.label or label
            added = existing.added or added
        entries[jid] = Entry(jid=jid, allow=caps, label=label, added=added)

    return entries


def _write_doc(entries: Dict[str, Entry], path: Path) -> Path:
    """Atomic write with no validation and no locking (callers hold the lock)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    doc = {
        "version": ALLOWLIST_VERSION,
        "updated": _now(),
        "entries": [entries[j].to_json() for j in sorted(entries)],
    }
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    os.replace(tmp, path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return path


@contextmanager
def _write_lock(path: Path):
    """Serialise read-modify-write between CLI processes.

    Without this, `unallow` and a concurrent `allow` both load the file, then both
    write their own snapshot — and the revocation is silently undone. flock is
    per-open-file-description, so this must wrap the *whole* load+mutate+write.
    """
    if fcntl is None:  # pragma: no cover - non-POSIX
        yield
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_suffix(path.suffix + ".lock")
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def mutate_allowlist(mutator, path: Optional[Path] = None) -> Dict[str, Entry]:
    """Locked read-modify-write. ``mutator(entries)`` edits in place and may return
    a value, which is passed through. Raises :class:`AllowlistError` unchanged."""
    path = path or allowlist_path()
    with _write_lock(path):
        # A missing file is an empty allowlist (first grant); a corrupt one still
        # raises, so mutation never overwrites something a human must inspect.
        entries = load_allowlist(path) if path.exists() else {}
        mutator(entries)
        _write_doc(entries, path)
        return entries


def save_allowlist(entries: Dict[str, Entry], path: Optional[Path] = None) -> Path:
    """Persist the allowlist atomically.  Refuses to clobber a corrupt file."""
    path = path or allowlist_path()
    with _write_lock(path):
        if path.exists():
            # A corrupt file must be repaired by hand; overwriting it would destroy
            # whatever the human meant to keep.
            load_allowlist(path)
        return _write_doc(entries, path)


# --------------------------------------------------------------------------- #
# the decision
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class Decision:
    """Outcome of consulting the gate.  Truthy only when the send may proceed."""

    allowed: bool
    code: str
    reason: str
    jid: Optional[str] = None
    label: str = ""
    capability: str = ""

    def __bool__(self) -> bool:  # so `if decision:` reads naturally
        return self.allowed


def _allow_hint(jid: Optional[str], capability: str) -> str:
    if not jid:
        return ""
    return (f"To permit this, run: python allowlist.py allow {jid} --caps {capability}")


def _sensitive_media(media_path: Optional[str]) -> bool:
    """True when media_path points at the gate's own state.

    The allowlist and audit log live here; sending either to a contact would hand
    over the policy and the recipients it protects. Checked by resolved path so a
    symlink cannot walk around it. Unresolvable paths fail closed.
    """
    if not media_path:
        return False
    try:
        target = Path(media_path).resolve()
        cfg = allowlist_path().parent.resolve()
        return target == cfg or cfg in target.parents
    except Exception:  # noqa: BLE001 - fail closed
        return True


def check_send(recipient: str, capability: str, media_path: Optional[str] = None) -> Decision:
    """Decide whether ``capability`` may be sent to ``recipient``.

    Order matters: input validation, then the (fail-closed) file, then the
    grant, then the operator kill switch, then dry-run.  Every branch that does
    not end in :class:`Decision` truthiness means *do not send*.
    """
    cap = (capability or "").strip(" \t\r\n").lower()
    decision: Decision

    if cap not in CAPABILITIES:
        decision = Decision(False, "unknown_capability",
                            f"Refused: unknown capability {capability!r} "
                            f"(expected one of {', '.join(CAPABILITIES)}).",
                            capability=cap)
        _audit(recipient, cap, decision, media_path)
        return decision

    jid = normalize_jid(recipient)
    if not jid:
        decision = Decision(False, "bad_recipient",
                            f"Refused: recipient {recipient!r} is not a phone number or JID.",
                            capability=cap)
        _audit(recipient, cap, decision, media_path)
        return decision

    try:
        entries = load_allowlist()
    except AllowlistError as exc:
        decision = Decision(False, "allowlist_unusable",
                            f"Refused: {exc.reason}. Nothing may be sent until this is fixed.",
                            jid=jid, capability=cap)
        _audit(recipient, cap, decision, media_path)
        return decision

    entry = entries.get(jid)
    if entry is None:
        decision = Decision(False, "not_allowlisted",
                            f"Refused: {jid} ({jid_kind(jid)}) is not on the send allowlist. "
                            + _allow_hint(jid, cap),
                            jid=jid, capability=cap)
        _audit(recipient, cap, decision, media_path)
        return decision

    if cap not in entry.allow:
        decision = Decision(False, "capability_not_granted",
                            f"Refused: {entry.label or jid} may receive "
                            f"[{', '.join(entry.allow) or 'nothing'}] but not '{cap}'. "
                            + _allow_hint(jid, cap),
                            jid=jid, label=entry.label, capability=cap)
        _audit(recipient, cap, decision, media_path)
        return decision

    if _sensitive_media(media_path):
        decision = Decision(False, "sensitive_media_path",
                            "Refused: that path is inside the allowlist directory and "
                            "may not be sent.",
                            jid=jid, label=entry.label, capability=cap)
        _audit(recipient, cap, decision, media_path)
        return decision

    if send_disabled():
        decision = Decision(False, "kill_switch",
                            "Refused: WHATSAPP_MCP_SEND_DISABLED is set; all sends are blocked.",
                            jid=jid, label=entry.label, capability=cap)
        _audit(recipient, cap, decision, media_path)
        return decision

    if dry_run_enabled():
        decision = Decision(False, "dry_run",
                            f"DRY RUN: would send '{cap}' to {entry.label or jid} ({jid}). "
                            "Nothing was sent (WHATSAPP_MCP_SEND_DRY_RUN is set).",
                            jid=jid, label=entry.label, capability=cap)
        _audit(recipient, cap, decision, media_path)
        return decision

    decision = Decision(True, "allowed", f"allowed: {cap} -> {jid}",
                        jid=jid, label=entry.label, capability=cap)
    _audit(recipient, cap, decision, media_path)
    return decision


# --------------------------------------------------------------------------- #
# audit trail
# --------------------------------------------------------------------------- #

def _audit(recipient: str, capability: str, decision: Decision,
           media_path: Optional[str] = None) -> None:
    """Append one JSONL record per attempt.  Never raises: auditing must not
    become a new way for a send to fail or succeed.

    The log holds raw recipients, so it is created 0600 inside a 0700 directory
    (matching the Go gate). Previously it inherited 0644 from the umask, which on
    a shared host published exactly the phone numbers it was added to protect.
    """
    try:
        path = audit_path()
        os.makedirs(path.parent, mode=0o700, exist_ok=True)
        record = {
            "ts": _now(),
            "source": "mcp",
            "requested": recipient,
            "jid": decision.jid,
            "label": decision.label,
            "capability": capability,
            "decision": decision.code,
            "allowed": decision.allowed,
            "media_path": media_path or "",
            "reason": decision.reason,
        }
        fd = os.open(path, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
        try:
            os.write(fd, (json.dumps(record, ensure_ascii=False) + "\n").encode("utf-8"))
        finally:
            os.close(fd)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    except Exception:  # noqa: BLE001 - audit failures are swallowed by design
        pass


# --------------------------------------------------------------------------- #
# name resolution (best effort, read-only, local DB only)
# --------------------------------------------------------------------------- #

def resolve_name(query: str, db_path: Optional[Path] = None) -> Tuple[List[Tuple[str, str]], str]:
    """Resolve a display name to candidate JIDs using the local bridge DB.

    Returns ``(candidates, error)``.  Candidates are ``(jid, name)`` pairs match-
    ing case-insensitively as a substring.  Never raises — callers fall back to
    demanding an explicit JID.
    """
    db_path = db_path or _MSG_DB_PATH
    if not db_path.exists():
        return [], f"no local messages.db at {db_path}; pass an explicit JID or phone number"
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        try:
            rows = conn.execute(
                "SELECT jid, COALESCE(name,'') FROM chats WHERE name LIKE ? ORDER BY last_message_time DESC",
                (f"%{query}%",),
            ).fetchall()
        finally:
            conn.close()
    except sqlite3.Error as exc:
        return [], f"could not read local chat database ({exc}); pass an explicit JID"
    return [(str(j), str(n)) for j, n in rows], ""


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def _print_entries(entries: Dict[str, Entry], as_json: bool) -> None:
    if as_json:
        print(json.dumps([entries[j].to_json() for j in sorted(entries)], indent=2))
        return
    if not entries:
        print("Allowlist is empty — every send is refused.")
        return
    print(f"{'JID':<42} {'KIND':<20} {'CAPS':<16} LABEL")
    for jid in sorted(entries):
        entry = entries[jid]
        print(f"{jid:<42} {jid_kind(jid):<20} "
              f"{','.join(entry.allow) or '(none)':<16} {entry.label}")


def main(argv: Optional[Iterable[str]] = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        prog="allowlist.py",
        description="Manage the WhatsApp MCP send allowlist (fail-closed).",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("path", help="print the allowlist path in effect")

    p_list = sub.add_parser("list", help="show what may be sent to")
    p_list.add_argument("--json", action="store_true")

    p_allow = sub.add_parser("allow", help="grant capabilities to a recipient")
    p_allow.add_argument("recipient", help="JID, phone number, or (best effort) a chat name")
    p_allow.add_argument("--caps", default="text",
                         help="comma separated subset of text,file,audio (default: text)")
    p_allow.add_argument("--label", default="", help="human-readable note")
    p_allow.add_argument("--json", action="store_true")

    p_un = sub.add_parser("unallow", help="revoke a recipient entirely")
    p_un.add_argument("recipient", help="JID, phone number, or stored label")

    p_chk = sub.add_parser("check", help="dry-run the gate for one recipient")
    p_chk.add_argument("recipient")
    p_chk.add_argument("--capability", default="text", choices=list(CAPABILITIES))

    args = parser.parse_args(list(argv) if argv is not None else None)

    if args.cmd == "path":
        print(allowlist_path())
        return 0

    if args.cmd == "list":
        try:
            entries = load_allowlist()
        except AllowlistError as exc:
            print(f"error: {exc.reason}", file=sys.stderr)
            print("Sends are refused until this is fixed.", file=sys.stderr)
            return 4
        _print_entries(entries, args.json)
        return 0

    if args.cmd == "check":
        decision = check_send(args.recipient, args.capability)
        print(decision.reason)
        return 0 if decision.allowed else 3

    if args.cmd == "unallow":
        target = normalize_jid(args.recipient)
        if not target:
            # Still allow revocation by stored label when the input is not a JID.
            try:
                entries = load_allowlist()
            except AllowlistError as exc:
                print(f"error: {exc.reason}", file=sys.stderr)
                return 4
            needle = args.recipient.strip().lower()
            matches = [e for e in entries.values() if e.label.strip().lower() == needle]
            if len(matches) > 1:
                print("ambiguous label, use a JID:", file=sys.stderr)
                for e in matches:
                    print(f"  {e.jid}  {e.label}", file=sys.stderr)
                return 2
            if len(matches) == 1:
                target = matches[0].jid

        if not target:
            print(f"not on allowlist: {args.recipient}", file=sys.stderr)
            return 2

        removed_holder: List[Entry] = []

        def _revoke(entries: Dict[str, Entry]) -> None:
            entry = entries.pop(target, None)
            if entry is not None:
                removed_holder.append(entry)

        try:
            mutate_allowlist(_revoke)
        except AllowlistError as exc:
            print(f"error: {exc.reason}", file=sys.stderr)
            return 4

        if not removed_holder:
            print(f"not on allowlist: {target}", file=sys.stderr)
            return 2
        removed = removed_holder[0]
        print(f"revoked {removed.jid} ({removed.label or 'no label'})")
        return 0

    if args.cmd == "allow":
        caps = tuple(sorted({c.strip().lower() for c in args.caps.split(",") if c.strip()}))
        unknown = [c for c in caps if c not in CAPABILITIES]
        if unknown or not caps:
            print(f"error: unknown capabilities {unknown or '(none given)'}; "
                  f"choose from {', '.join(CAPABILITIES)}", file=sys.stderr)
            return 1

        jid = normalize_jid(args.recipient)
        label = args.label
        if not jid:
            candidates, err = resolve_name(args.recipient)
            if err:
                print(f"error: {err}", file=sys.stderr)
                return 2
            if not candidates:
                print(f"no chat matches {args.recipient!r}; pass a JID or phone number",
                      file=sys.stderr)
                return 2
            if len(candidates) > 1:
                print(f"{args.recipient!r} is ambiguous — re-run with a JID:", file=sys.stderr)
                for cjid, cname in candidates:
                    print(f"  python allowlist.py allow {cjid} --caps {args.caps}"
                          f" --label {cname!r}", file=sys.stderr)
                return 2
            jid, resolved_label = candidates[0]
            label = label or resolved_label

        # Show the resolved target BEFORE persisting — enabling a recipient must
        # be a deliberate act, not a side effect of a typo.
        print(f"resolved: {jid}  kind={jid_kind(jid)}  label={label or '(none)'}  caps={','.join(caps)}")

        def _grant(entries: Dict[str, Entry]) -> None:
            entries[jid] = Entry(jid=jid, allow=caps, label=label, added=_now())

        try:
            mutate_allowlist(_grant)
        except AllowlistError as exc:
            print(f"error: {exc.reason}", file=sys.stderr)
            print("Refusing to overwrite it; fix or delete the file by hand.", file=sys.stderr)
            return 4
        print(f"wrote {allowlist_path()}")
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
