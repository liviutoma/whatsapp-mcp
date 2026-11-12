package main

// Tests for the /api/send handler wiring. These exist because a review showed the
// entire gate could be deleted from the handler while every other test stayed
// green: the suite covered checkSend but never proved it was *reached*.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// makeHandler returns the handler plus a recorder closure for the sender seam.
func makeHandler(t *testing.T) (http.HandlerFunc, *[]SendMessageRequest, *bool) {
	t.Helper()
	dir := isolate(t)
	allowOnly(t, dir, testPerson, `"text"`)
	calls := &[]SendMessageRequest{}
	ok := new(bool)
	*ok = true

	h := handleSend(func(recipient, message, mediaPath string) (bool, string) {
		*calls = append(*calls, SendMessageRequest{Recipient: recipient, Message: message, MediaPath: mediaPath})
		return *ok, "sent"
	})
	return h, calls, ok
}

func post(t *testing.T, h http.HandlerFunc, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/send", strings.NewReader(body))
	rec := httptest.NewRecorder()
	h(rec, req)
	return rec
}

func TestHandlerRejectsNonPost(t *testing.T) {
	h, calls, _ := makeHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/api/send", nil)
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("want 405, got %d", rec.Code)
	}
	if len(*calls) != 0 {
		t.Fatal("sender must not be called")
	}
}

func TestHandlerRejectsMissingFields(t *testing.T) {
	h, calls, _ := makeHandler(t)
	for _, body := range []string{`{`, `{}`, `{"recipient":"` + testPerson + `"}`} {
		if rec := post(t, h, body); rec.Code != http.StatusBadRequest {
			t.Fatalf("body %q: want 400, got %d", body, rec.Code)
		}
	}
	if len(*calls) != 0 {
		t.Fatal("sender must not be called for malformed requests")
	}
}

func TestHandlerRefusesUnlistedRecipient(t *testing.T) {
	h, calls, _ := makeHandler(t)
	rec := post(t, h, `{"recipient":"`+testGroup+`","message":"hi"}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d: %s", rec.Code, rec.Body.String())
	}
	if len(*calls) != 0 {
		t.Fatal("sender must not be called when the gate refuses")
	}
	var resp SendMessageResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Success {
		t.Fatal("refusal body must report success=false")
	}
}

func TestHandlerSendsAllowedText(t *testing.T) {
	h, calls, _ := makeHandler(t)
	rec := post(t, h, `{"recipient":"`+testPerson+`","message":"hello"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if len(*calls) != 1 {
		t.Fatalf("want exactly 1 send, got %d", len(*calls))
	}
	// The gated recipient string is the one that must reach the sender.
	if (*calls)[0].Recipient != testPerson || (*calls)[0].Message != "hello" {
		t.Fatalf("unexpected send: %+v", (*calls)[0])
	}
}

// The core defect: the capability label was taken on trust while the payload was
// sent regardless, so a text-only grant could carry a file.
func TestHandlerRejectsCapabilitySpoof(t *testing.T) {
	h, calls, _ := makeHandler(t)
	cases := []string{
		`{"recipient":"` + testPerson + `","media_path":"/etc/hosts","capability":"text"}`,
		`{"recipient":"` + testPerson + `","message":"x","capability":"file"}`,
		`{"recipient":"` + testPerson + `","media_path":"/tmp/v.ogg","capability":"file"}`,
	}
	for _, body := range cases {
		rec := post(t, h, body)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("body %s: want 400 (capability/payload mismatch), got %d: %s",
				body, rec.Code, rec.Body.String())
		}
	}
	if len(*calls) != 0 {
		t.Fatalf("sender must never be called on a mismatch, got %d calls", len(*calls))
	}
}

func TestHandlerDerivesCapabilityFromMedia(t *testing.T) {
	dir := isolate(t)
	// Only 'file' granted, no 'audio'.
	allowOnly(t, dir, testPerson, `"file"`)

	calls := &[]SendMessageRequest{}
	stub := func(recipient, message, mediaPath string) (bool, string) {
		*calls = append(*calls, SendMessageRequest{Recipient: recipient, MediaPath: mediaPath})
		return true, "sent"
	}
	h := handleSend(stub)

	// A .pdf with no declared capability is a file -> allowed.
	rec := post(t, h, `{"recipient":"`+testPerson+`","media_path":"/tmp/doc.pdf","message":"see attached"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("pdf should be allowed under 'file': %d %s", rec.Code, rec.Body.String())
	}
	if len(*calls) != 1 {
		t.Fatalf("want 1 send, got %d", len(*calls))
	}

	// A .ogg is delivered as a PTT voice note, so it needs 'audio' — which was
	// never granted. This must be refused even though 'file' is granted.
	*calls = nil
	rec = post(t, h, `{"recipient":"`+testPerson+`","media_path":"/tmp/voice.ogg"}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("ogg must need 'audio', got %d: %s", rec.Code, rec.Body.String())
	}
	if len(*calls) != 0 {
		t.Fatal("sender must not be called for an ogg without the audio grant")
	}
}

func TestHandlerAudioGrantAllowsOgg(t *testing.T) {
	dir := isolate(t)
	allowOnly(t, dir, testPerson, `"audio"`)

	calls := 0
	h := handleSend(func(recipient, message, mediaPath string) (bool, string) {
		calls++
		return true, "sent"
	})
	rec := post(t, h, `{"recipient":"`+testPerson+`","media_path":"/tmp/voice.ogg","capability":"audio"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if calls != 1 {
		t.Fatalf("want 1 send, got %d", calls)
	}
}

func TestHandlerSurfacesSendFailure(t *testing.T) {
	dir := isolate(t)
	allowOnly(t, dir, testPerson, `"text"`)
	h := handleSend(func(recipient, message, mediaPath string) (bool, string) {
		return false, "Not connected to WhatsApp"
	})
	rec := post(t, h, `{"recipient":"`+testPerson+`","message":"hi"}`)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("want 500 on send failure, got %d", rec.Code)
	}
}

func TestHandlerKillSwitch(t *testing.T) {
	h, calls, _ := makeHandler(t)
	t.Setenv("WHATSAPP_MCP_SEND_DISABLED", "1")
	rec := post(t, h, `{"recipient":"`+testPerson+`","message":"hi"}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("want 403 under kill switch, got %d", rec.Code)
	}
	if len(*calls) != 0 {
		t.Fatal("sender must not be called under the kill switch")
	}
}

func TestHandlerBoundedBody(t *testing.T) {
	h, _, _ := makeHandler(t)
	huge := `{"recipient":"` + testPerson + `","message":"` + strings.Repeat("a", maxSendBody+10) + `"}`
	if rec := post(t, h, huge); rec.Code != http.StatusBadRequest {
		t.Fatalf("oversized body should be rejected, got %d", rec.Code)
	}
}

// ---- load-level and normalisation regressions -------------------------------

func TestLoadLevelCapabilityFilter(t *testing.T) {
	dir := isolate(t)
	allowOnly(t, dir, testPerson, `"text","bogus","TEXT"`)
	entries, err := loadAllowlist()
	if err != nil {
		t.Fatal(err)
	}
	// "TEXT" must NOT be case-folded into a grant: Python matches exactly, so
	// folding here would have made Go strictly more permissive than the MCP path.
	got := entries[testPerson].Allow
	if len(got) != 1 || got[0] != "text" {
		t.Fatalf("want [text], got %v", got)
	}
}

func TestMissingEntriesRefused(t *testing.T) {
	dir := isolate(t)
	writeAllowlist(t, dir, `{"version":1}`)
	if d := checkSend(testPerson, "text"); d.Allowed || d.Code != "allowlist_unusable" {
		t.Fatalf("missing entries must fail closed, got %+v", d)
	}
}

func TestMissingAllowRefused(t *testing.T) {
	dir := isolate(t)
	writeAllowlist(t, dir, `{"version":1,"entries":[{"jid":"`+testPerson+`"}]}`)
	d := checkSend(testPerson, "text")
	if d.Allowed || d.Code != "allowlist_unusable" {
		t.Fatalf("entry without 'allow' must fail the whole file closed, got %+v", d)
	}
}

func TestNonAsciiDigitsRejected(t *testing.T) {
	dir := isolate(t)
	allowOnly(t, dir, "4915@s.whatsapp.net", `"text"`)
	// ASCII "4915" + Arabic-Indic digits must not collapse onto "4915".
	for _, r := range []string{"4915\u0666\u0663", "\u0664\u0669\u0661\u0665", "4915\uff11\uff15"} {
		if d := checkSend(r, "text"); d.Allowed {
			t.Fatalf("%q must not match 4915, got %+v", r, d)
		}
	}
}

func TestMediaCapability(t *testing.T) {
	cases := map[string]string{
		"":               "text",
		"/tmp/voice.ogg": "audio",
		"/tmp/VOICE.OGG": "audio",
		"/tmp/song.mp3":  "file",
		"/tmp/doc.pdf":   "file",
		"/tmp/noext":     "file",
	}
	for in, want := range cases {
		if got := mediaCapability(in); got != want {
			t.Errorf("mediaCapability(%q) = %q want %q", in, got, want)
		}
	}
}

func TestExpandTildeOnlyHandlesBareAndSlash(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home")
	}
	if got := expandTilde("~/x.json"); got != filepath.Join(home, "x.json") {
		t.Fatalf("~/ expansion wrong: %q", got)
	}
	if got := expandTilde("~"); got != home {
		t.Fatalf("bare ~ wrong: %q", got)
	}
	// "~user" must stay literal: Python treats it as a literal path, so expanding
	// it here would make the two gates consult different files.
	if got := expandTilde("~deploy/x.json"); got != "~deploy/x.json" {
		t.Fatalf("~user must not expand, got %q", got)
	}
}
