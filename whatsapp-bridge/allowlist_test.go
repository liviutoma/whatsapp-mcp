package main

import (
	"os"
	"path/filepath"
	"testing"
)

const (
	testPerson = "15550100001@s.whatsapp.net"
	testGroup  = "120363000000000000@g.us"
	testLID    = "100000000000001@lid"
)

// isolate points the gate at a per-test allowlist/audit file and clears flags.
func isolate(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("WHATSAPP_MCP_ALLOWLIST", filepath.Join(dir, "send-allowlist.json"))
	t.Setenv("WHATSAPP_MCP_AUDIT_LOG", filepath.Join(dir, "send-audit.jsonl"))
	t.Setenv("WHATSAPP_MCP_SEND_DISABLED", "")
	t.Setenv("WHATSAPP_MCP_SEND_DRY_RUN", "")
	return dir
}

func writeAllowlist(t *testing.T, dir, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "send-allowlist.json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func allowOnly(t *testing.T, dir, jid string, caps string) {
	t.Helper()
	writeAllowlist(t, dir, `{"version":1,"entries":[{"jid":"`+jid+`","label":"x","allow":[`+caps+`],"added":""}]}`)
}

func TestNormalizeJIDMatchesPython(t *testing.T) {
	cases := []struct{ in, want string }{
		{"15550100001@s.whatsapp.net", "15550100001@s.whatsapp.net"},
		{"+1 555 010 0002", "15550100002@s.whatsapp.net"},
		{"15550100002", "15550100002@s.whatsapp.net"},
		{"120363000000000000@g.us", "120363000000000000@g.us"},
		{testLID, testLID},
		{"15550100001:12@s.whatsapp.net", "15550100001@s.whatsapp.net"},
		{"15550100001@C.US", "15550100001@s.whatsapp.net"},
		{"15550100001@S.WHATSAPP.NET", "15550100001@s.whatsapp.net"},
	}
	for _, c := range cases {
		got, ok := normalizeJID(c.in)
		if !ok || got != c.want {
			t.Errorf("normalizeJID(%q) = %q,%v want %q", c.in, got, ok, c.want)
		}
	}
}

func TestNormalizeJIDRejects(t *testing.T) {
	for _, in := range []string{"", "   ", "status", "@s.whatsapp.net", "no-digits", "user@", "@"} {
		if got, ok := normalizeJID(in); ok {
			t.Errorf("normalizeJID(%q) should fail, got %q", in, got)
		}
	}
}

func TestDeviceSuffixCannotDodgeEntry(t *testing.T) {
	dir := isolate(t)
	allowOnly(t, dir, testPerson, `"text"`)
	if d := checkSend("15550100001:7@s.whatsapp.net", "text"); !d.Allowed {
		t.Fatalf("device-suffixed JID should match: %s", d.Reason)
	}
}

// ---- fail closed -----------------------------------------------------------

func TestMissingFileRefuses(t *testing.T) {
	isolate(t)
	d := checkSend(testPerson, "text")
	if d.Allowed || d.Code != "allowlist_unusable" {
		t.Fatalf("want allowlist_unusable, got %+v", d)
	}
}

func TestEmptyFileRefuses(t *testing.T) {
	dir := isolate(t)
	writeAllowlist(t, dir, "   \n")
	if d := checkSend(testPerson, "text"); d.Allowed || d.Code != "allowlist_unusable" {
		t.Fatalf("want refusal, got %+v", d)
	}
}

func TestCorruptFileRefuses(t *testing.T) {
	dir := isolate(t)
	writeAllowlist(t, dir, "{not json")
	d := checkSend(testPerson, "text")
	if d.Allowed || d.Code != "allowlist_unusable" {
		t.Fatalf("want refusal, got %+v", d)
	}
}

func TestMissingVersionRefuses(t *testing.T) {
	dir := isolate(t)
	writeAllowlist(t, dir, `{"entries":[]}`)
	if d := checkSend(testPerson, "text"); d.Allowed {
		t.Fatalf("missing version must refuse, got %+v", d)
	}
}

func TestWrongVersionRefuses(t *testing.T) {
	dir := isolate(t)
	writeAllowlist(t, dir, `{"version":99,"entries":[]}`)
	if d := checkSend(testPerson, "text"); d.Allowed {
		t.Fatalf("wrong version must refuse, got %+v", d)
	}
}

func TestEmptyEntriesRefuses(t *testing.T) {
	dir := isolate(t)
	writeAllowlist(t, dir, `{"version":1,"entries":[]}`)
	d := checkSend(testPerson, "text")
	if d.Allowed || d.Code != "not_allowlisted" {
		t.Fatalf("want not_allowlisted, got %+v", d)
	}
}

// ---- authorisation ---------------------------------------------------------

func TestAllowedText(t *testing.T) {
	dir := isolate(t)
	allowOnly(t, dir, testPerson, `"text"`)
	d := checkSend(testPerson, "text")
	if !d.Allowed || d.Code != "allowed" || d.JID != testPerson {
		t.Fatalf("want allowed, got %+v", d)
	}
}

func TestAllowedViaBarePhone(t *testing.T) {
	dir := isolate(t)
	allowOnly(t, dir, testPerson, `"text"`)
	if d := checkSend("+1 555 010 0001", "text"); !d.Allowed {
		t.Fatalf("bare phone should match: %s", d.Reason)
	}
}

func TestUnlistedRefused(t *testing.T) {
	dir := isolate(t)
	allowOnly(t, dir, testPerson, `"text"`)
	d := checkSend(testGroup, "text")
	if d.Allowed || d.Code != "not_allowlisted" {
		t.Fatalf("want not_allowlisted, got %+v", d)
	}
}

func TestCapabilityNotGranted(t *testing.T) {
	dir := isolate(t)
	allowOnly(t, dir, testPerson, `"text"`)
	d := checkSend(testPerson, "file")
	if d.Allowed || d.Code != "capability_not_granted" {
		t.Fatalf("want capability_not_granted, got %+v", d)
	}
}

func TestAudioGrantIsIndependentOfFile(t *testing.T) {
	dir := isolate(t)
	allowOnly(t, dir, testPerson, `"text","audio"`)
	if d := checkSend(testPerson, "audio"); !d.Allowed {
		t.Fatalf("audio should be allowed: %s", d.Reason)
	}
	if d := checkSend(testPerson, "file"); d.Allowed {
		t.Fatal("file must still be refused when only audio is granted")
	}
}

func TestUnknownCapabilityInEntryGrantsNothing(t *testing.T) {
	dir := isolate(t)
	allowOnly(t, dir, testPerson, `"text","bogus"`)
	if d := checkSend(testPerson, "bogus"); d.Allowed {
		t.Fatal("unknown capability must never authorise a send")
	}
	if d := checkSend(testPerson, "text"); !d.Allowed {
		t.Fatal("known capability should still work")
	}
}

func TestUnknownCapabilityRequestRefused(t *testing.T) {
	dir := isolate(t)
	allowOnly(t, dir, testPerson, `"text"`)
	if d := checkSend(testPerson, "admin"); d.Allowed || d.Code != "unknown_capability" {
		t.Fatalf("want unknown_capability, got %+v", d)
	}
}

func TestDuplicateEntriesNarrow(t *testing.T) {
	dir := isolate(t)
	writeAllowlist(t, dir, `{"version":1,"entries":[
		{"jid":"`+testPerson+`","label":"a","allow":["text"],"added":""},
		{"jid":"`+testPerson+`","label":"b","allow":["file"],"added":""}]}`)
	entries, err := loadAllowlist()
	if err != nil {
		t.Fatal(err)
	}
	if n := len(entries[testPerson].Allow); n != 0 {
		t.Fatalf("intersection should be empty, got %v", entries[testPerson].Allow)
	}
	if d := checkSend(testPerson, "text"); d.Allowed {
		t.Fatal("narrowed entry must not authorise text")
	}
}

func TestBadRecipient(t *testing.T) {
	dir := isolate(t)
	allowOnly(t, dir, testPerson, `"text"`)
	if d := checkSend("not-a-recipient", "text"); d.Allowed || d.Code != "bad_recipient" {
		t.Fatalf("want bad_recipient, got %+v", d)
	}
}

func TestGroupAndLIDCanBeAllowed(t *testing.T) {
	dir := isolate(t)
	writeAllowlist(t, dir, `{"version":1,"entries":[
		{"jid":"`+testGroup+`","label":"Test Group","allow":["text"],"added":""},
		{"jid":"`+testLID+`","label":"Lid","allow":["text"],"added":""}]}`)
	if d := checkSend(testGroup, "text"); !d.Allowed {
		t.Fatalf("group should be allowed: %s", d.Reason)
	}
	if d := checkSend(testLID, "text"); !d.Allowed {
		t.Fatalf("lid should be allowed: %s", d.Reason)
	}
}

// ---- operator controls -----------------------------------------------------

func TestKillSwitchOverridesAllowlist(t *testing.T) {
	dir := isolate(t)
	allowOnly(t, dir, testPerson, `"text"`)
	t.Setenv("WHATSAPP_MCP_SEND_DISABLED", "1")
	d := checkSend(testPerson, "text")
	if d.Allowed || d.Code != "kill_switch" {
		t.Fatalf("want kill_switch, got %+v", d)
	}
}

func TestDryRunNeverAllows(t *testing.T) {
	dir := isolate(t)
	allowOnly(t, dir, testPerson, `"text"`)
	t.Setenv("WHATSAPP_MCP_SEND_DRY_RUN", "1")
	d := checkSend(testPerson, "text")
	if d.Allowed || d.Code != "dry_run" {
		t.Fatalf("want dry_run, got %+v", d)
	}
}

// ---- audit -----------------------------------------------------------------

func TestAuditRecordsDecision(t *testing.T) {
	dir := isolate(t)
	allowOnly(t, dir, testPerson, `"text"`)
	checkSend(testPerson, "text")
	checkSend(testGroup, "text")

	raw, err := os.ReadFile(filepath.Join(dir, "send-audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if n := len(splitLines(string(raw))); n != 2 {
		t.Fatalf("want 2 audit lines, got %d: %s", n, raw)
	}
	if !contains(string(raw), `"allowed":true`) || !contains(string(raw), `"decision":"not_allowlisted"`) {
		t.Fatalf("audit content unexpected: %s", raw)
	}
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			if i > start {
				out = append(out, s[start:i])
			}
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && indexOf(haystack, needle) >= 0
}

func indexOf(h, n string) int {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return i
		}
	}
	return -1
}
