package main

// Fail-closed send allowlist for the WhatsApp bridge.
//
// The Python MCP server enforces this same policy, but the bridge is a plain
// HTTP API: any local process can POST /api/send directly and skip the MCP
// layer entirely. Gating here too means there is no path to whatsmeow's
// SendMessage that does not consult the allowlist (the history-sync bootstrap
// is the single deliberate exception, and it is not user-controlled).
//
// Contract is identical to whatsapp-mcp-server/allowlist.py so that one file
// governs both processes:
//   * nothing allowed unless the exact JID is listed;
//   * grants are per capability (text/file/audio);
//   * missing/empty/corrupt/unsupported-version allowlist => refuse everything;
//   * display names never authorise anything.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const allowlistVersion = 1

var capabilities = map[string]bool{"text": true, "file": true, "audio": true}

// AllowEntry is one allowlisted recipient (runtime form).
type AllowEntry struct {
	JID   string
	Label string
	Allow []string
	Added string
}

// allowEntryJSON is the wire form. `Allow` is a pointer so a missing or null
// `allow` is rejected rather than decoding to a nil slice, which would have let a
// malformed entry silently grant nothing instead of failing the whole file closed
// (as the Python gate does).
type allowEntryJSON struct {
	JID   string    `json:"jid"`
	Label string    `json:"label"`
	Allow *[]string `json:"allow"`
	Added string    `json:"added"`
}

type allowlistDoc struct {
	Version *int   `json:"version"`
	Updated string `json:"updated"`
	// Pointer so a missing/null `entries` is distinguishable from an empty list:
	// the Python gate treats the former as corrupt, and this must agree.
	Entries *[]allowEntryJSON `json:"entries"`
}

// Decision is the outcome of consulting the gate. Allowed==true is the only
// value that may result in a send.
type Decision struct {
	Allowed    bool
	Code       string
	Reason     string
	JID        string
	Label      string
	Capability string
}

// expandTilde expands only "~" and "~/..." — the same rule as the Python gate.
// Treating any leading "~" as $HOME (the previous behaviour) made "~user/x"
// resolve to $HOME/user/x here but to a literal path there, so the two
// enforcement points could read different files.
func expandTilde(v string) string {
	home, err := os.UserHomeDir()
	if err != nil {
		return v
	}
	if v == "~" {
		return home
	}
	if strings.HasPrefix(v, "~/") {
		return filepath.Join(home, strings.TrimPrefix(v, "~/"))
	}
	return v
}

func allowlistPath() string {
	if v := strings.Trim(os.Getenv("WHATSAPP_MCP_ALLOWLIST"), " \t\r\n"); v != "" {
		return expandTilde(v)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "send-allowlist.json"
	}
	return filepath.Join(home, ".config", "whatsapp-mcp", "send-allowlist.json")
}

func auditPath() string {
	if v := strings.Trim(os.Getenv("WHATSAPP_MCP_AUDIT_LOG"), " \t\r\n"); v != "" {
		return expandTilde(v)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "send-audit.jsonl"
	}
	return filepath.Join(home, ".config", "whatsapp-mcp", "send-audit.jsonl")
}

func envFlag(name string) bool {
	// ASCII-only trim, matching the Python gate. strings.TrimSpace would treat
	// U+001C-001F as non-space while Python's str.strip() strips them, letting
	// WHATSAPP_MCP_SEND_DISABLED=$'\x1c1' read as ON in one gate and OFF in the other.
	switch strings.ToLower(strings.Trim(os.Getenv(name), " \t\r\n")) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// sendDisabled is the operator kill switch.
func sendDisabled() bool { return envFlag("WHATSAPP_MCP_SEND_DISABLED") }

// dryRun reports the would-be target without sending.
func dryRun() bool { return envFlag("WHATSAPP_MCP_SEND_DRY_RUN") }

// Character sets permitted in each position. Validated, never filtered: filtering
// is what let `"4915" + Arabic-Indic digits` normalise to an allowlisted
// `4915@s.whatsapp.net` while being a different string entirely.
func allowedRunes(s string, set string) bool {
	for _, r := range s {
		if !strings.ContainsRune(set, r) {
			return false
		}
	}
	return true
}

const (
	bareAllowed   = "0123456789+-() "
	userAllowed   = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
	serverAllowed = "abcdefghijklmnopqrstuvwxyz0123456789.-"
)

// normalizeJID mirrors normalize_jid() in the Python gate exactly.
func normalizeJID(recipient string) (string, bool) {
	raw := strings.Trim(recipient, " \t\r\n")
	if raw == "" {
		return "", false
	}

	if strings.Contains(raw, "@") {
		idx := strings.Index(raw, "@")
		user := strings.Trim(raw[:idx], " \t\r\n")
		server := strings.ToLower(strings.Trim(raw[idx+1:], " \t\r\n"))
		if user == "" || server == "" {
			return "", false
		}
		// A second '@' is ambiguous to whatsmeow (it keeps only two parts), so the
		// gate and the sender could disagree about the destination.
		if strings.Contains(server, "@") || strings.Contains(user, "@") {
			return "", false
		}
		if server == "c.us" {
			server = "s.whatsapp.net"
		}
		if !allowedRunes(server, serverAllowed) {
			return "", false
		}
		// Drop a device suffix ("4917...:12@...") so it cannot dodge an entry.
		if c := strings.Index(user, ":"); c >= 0 {
			user = strings.Trim(user[:c], " \t\r\n")
		}
		if user == "" || !allowedRunes(user, userAllowed) {
			return "", false
		}
		return user + "@" + server, true
	}

	if !allowedRunes(raw, bareAllowed) {
		return "", false
	}
	var digits strings.Builder
	for _, r := range raw {
		if r >= '0' && r <= '9' {
			digits.WriteRune(r)
		}
	}
	if digits.Len() == 0 {
		return "", false
	}
	return digits.String() + "@s.whatsapp.net", true
}

// mediaCapability derives the capability a payload actually exercises. Callers
// must not name it themselves: a `text` grant carrying a media path, or a `file`
// grant carrying a .ogg (which the bridge sends as a PTT voice note), is exactly
// the bypass this closes. Mirrors media_capability() in allowlist.py.
func mediaCapability(mediaPath string) string {
	if strings.TrimSpace(mediaPath) == "" {
		return "text"
	}
	ext := ""
	if i := strings.LastIndex(mediaPath, "."); i >= 0 {
		ext = strings.ToLower(mediaPath[i+1:])
	}
	if ext == "ogg" {
		return "audio"
	}
	return "file"
}

// jidKind is for human-readable messages only; it never affects authorisation.
func jidKind(jid string) string {
	_, server, found := strings.Cut(jid, "@")
	if !found {
		return "unknown"
	}
	switch server {
	case "s.whatsapp.net":
		return "person"
	case "g.us":
		return "group"
	case "lid":
		return "person (privacy id)"
	case "newsletter":
		return "channel"
	case "broadcast":
		return "broadcast list"
	}
	return server
}

// loadAllowlist reads and validates the allowlist. Any problem is an error, and
// any error means the caller must refuse the send.
func loadAllowlist() (map[string]AllowEntry, error) {
	path := allowlistPath()
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("allowlist file not found at %s", path)
		}
		return nil, fmt.Errorf("allowlist unreadable (%v)", err)
	}
	if strings.TrimSpace(string(raw)) == "" {
		return nil, fmt.Errorf("allowlist is empty at %s", path)
	}

	var doc allowlistDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("allowlist is corrupt (invalid JSON: %v)", err)
	}
	if doc.Version == nil || *doc.Version != allowlistVersion {
		got := "missing"
		if doc.Version != nil {
			got = fmt.Sprintf("%d", *doc.Version)
		}
		return nil, fmt.Errorf("allowlist has unsupported version %s (expected %d)", got, allowlistVersion)
	}
	if doc.Entries == nil {
		return nil, fmt.Errorf("allowlist is corrupt (entries missing or null)")
	}

	entries := make(map[string]AllowEntry, len(*doc.Entries))
	for _, item := range *doc.Entries {
		jid, ok := normalizeJID(item.JID)
		if !ok {
			return nil, fmt.Errorf("allowlist contains an entry with an invalid jid: %q", item.JID)
		}
		if item.Allow == nil {
			return nil, fmt.Errorf("allowlist entry %s is missing an 'allow' list", jid)
		}
		// Unknown capability names grant nothing (fail closed, not open). Matched
		// exactly, as the Python gate does — case-folding here would have granted
		// `text` for a file that says `"TEXT"`, which Python refuses.
		var caps []string
		seen := map[string]bool{}
		for _, c := range *item.Allow {
			if capabilities[c] && !seen[c] {
				seen[c] = true
				caps = append(caps, c)
			}
		}
		if existing, dup := entries[jid]; dup {
			// Duplicates narrow, never widen: intersection of grants.
			var narrowed []string
			for _, c := range caps {
				for _, e := range existing.Allow {
					if c == e {
						narrowed = append(narrowed, c)
						break
					}
				}
			}
			caps = narrowed
			if existing.Label != "" {
				item.Label = existing.Label
			}
			if existing.Added != "" {
				item.Added = existing.Added
			}
		}
		entries[jid] = AllowEntry{JID: jid, Label: item.Label, Allow: caps, Added: item.Added}
	}
	return entries, nil
}

// sensitiveMediaPath reports whether mediaPath points at the gate's own state
// (the allowlist and audit log). Sending either to a contact would hand over the
// policy and the recipients it protects. Resolution is done first so a symlink
// cannot walk around it; an unresolvable path fails closed.
func sensitiveMediaPath(mediaPath string) bool {
	if strings.TrimSpace(mediaPath) == "" {
		return false
	}
	abs, err := filepath.Abs(mediaPath)
	if err != nil {
		return true
	}
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		abs = resolved
	}
	cfg, err := filepath.Abs(filepath.Dir(allowlistPath()))
	if err != nil {
		return true
	}
	if resolved, err := filepath.EvalSymlinks(cfg); err == nil {
		cfg = resolved
	}
	return abs == cfg || strings.HasPrefix(abs, cfg+string(filepath.Separator))
}

// checkSend decides whether capability may be sent to recipient (no media).
func checkSend(recipient, capability string) Decision {
	return checkSendMedia(recipient, capability, "")
}

// checkSendMedia also screens the media path, which the capability alone cannot.
func checkSendMedia(recipient, capability, mediaPath string) Decision {
	cap := strings.ToLower(strings.Trim(capability, " \t\r\n"))

	if !capabilities[cap] {
		d := Decision{Code: "unknown_capability", Capability: cap,
			Reason: fmt.Sprintf("Refused: unknown capability %q (expected one of text, file, audio).", capability)}
		audit(recipient, cap, d)
		return d
	}

	jid, ok := normalizeJID(recipient)
	if !ok {
		d := Decision{Code: "bad_recipient", Capability: cap,
			Reason: fmt.Sprintf("Refused: recipient %q is not a phone number or JID.", recipient)}
		audit(recipient, cap, d)
		return d
	}

	entries, err := loadAllowlist()
	if err != nil {
		d := Decision{Code: "allowlist_unusable", JID: jid, Capability: cap,
			Reason: fmt.Sprintf("Refused: %v. Nothing may be sent until this is fixed.", err)}
		audit(recipient, cap, d)
		return d
	}

	entry, found := entries[jid]
	if !found {
		d := Decision{Code: "not_allowlisted", JID: jid, Capability: cap,
			Reason: fmt.Sprintf("Refused: %s (%s) is not on the send allowlist. "+
				"To permit this, run: python allowlist.py allow %s --caps %s",
				jid, jidKind(jid), jid, cap)}
		audit(recipient, cap, d)
		return d
	}

	granted := false
	for _, c := range entry.Allow {
		if c == cap {
			granted = true
			break
		}
	}
	if !granted {
		label := entry.Label
		if label == "" {
			label = jid
		}
		d := Decision{Code: "capability_not_granted", JID: jid, Label: entry.Label, Capability: cap,
			Reason: fmt.Sprintf("Refused: %s may receive [%s] but not '%s'. "+
				"To permit this, run: python allowlist.py allow %s --caps %s",
				label, strings.Join(entry.Allow, ", "), cap, jid, cap)}
		audit(recipient, cap, d)
		return d
	}

	if sensitiveMediaPath(mediaPath) {
		d := Decision{Code: "sensitive_media_path", JID: jid, Label: entry.Label, Capability: cap,
			Reason: "Refused: that path is inside the allowlist directory and may not be sent."}
		audit(recipient, cap, d)
		return d
	}

	if sendDisabled() {
		d := Decision{Code: "kill_switch", JID: jid, Label: entry.Label, Capability: cap,
			Reason: "Refused: WHATSAPP_MCP_SEND_DISABLED is set; all sends are blocked."}
		audit(recipient, cap, d)
		return d
	}

	if dryRun() {
		label := entry.Label
		if label == "" {
			label = jid
		}
		d := Decision{Code: "dry_run", JID: jid, Label: entry.Label, Capability: cap,
			Reason: fmt.Sprintf("DRY RUN: would send '%s' to %s (%s). Nothing was sent.", cap, label, jid)}
		audit(recipient, cap, d)
		return d
	}

	d := Decision{Allowed: true, Code: "allowed", JID: jid, Label: entry.Label, Capability: cap,
		Reason: fmt.Sprintf("allowed: %s -> %s", cap, jid)}
	audit(recipient, cap, d)
	return d
}

// audit appends one JSONL record per attempt. Failures are swallowed: auditing
// must never become a way for a send to succeed or fail.
func audit(recipient, capability string, d Decision) {
	record := map[string]any{
		"ts":         time.Now().UTC().Format(time.RFC3339),
		"source":     "bridge",
		"requested":  recipient,
		"jid":        d.JID,
		"label":      d.Label,
		"capability": capability,
		"decision":   d.Code,
		"allowed":    d.Allowed,
		"reason":     d.Reason,
	}
	line, err := json.Marshal(record)
	if err != nil {
		return
	}
	path := auditPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(append(line, '\n'))
}
