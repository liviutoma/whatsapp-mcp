package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAllowlistCannotBeSentAsMedia(t *testing.T) {
	dir := isolate(t)
	allowOnly(t, dir, testPerson, `"file"`)
	for _, target := range []string{
		filepath.Join(dir, "send-allowlist.json"),
		filepath.Join(dir, "send-audit.jsonl"),
		dir,
	} {
		d := checkSend(testPerson, "file")
		_ = d
		if !sensitiveMediaPath(target) {
			t.Fatalf("%q should be treated as sensitive", target)
		}
	}
	if sensitiveMediaPath("/tmp/report.pdf") {
		t.Fatal("normal path must not be sensitive")
	}
	if sensitiveMediaPath("") {
		t.Fatal("empty path is not sensitive (it is a text send)")
	}
}

func TestSensitiveMediaRefusedEndToEnd(t *testing.T) {
	dir := isolate(t)
	allowOnly(t, dir, testPerson, `"file"`)
	allowlistFile := filepath.Join(dir, "send-allowlist.json")
	if _, err := os.Stat(allowlistFile); err != nil {
		t.Fatal(err)
	}
	h := handleSend(func(recipient, message, mediaPath string) (bool, string) {
		t.Fatal("sender must not be called")
		return false, ""
	})
	rec := post(t, h, `{"recipient":"`+testPerson+`","media_path":"`+allowlistFile+`","message":"x"}`)
	if rec.Code != 403 {
		t.Fatalf("want 403, got %d: %s", rec.Code, rec.Body.String())
	}
}
