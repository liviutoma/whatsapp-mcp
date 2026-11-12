# WhatsApp MCP Server

This is a Model Context Protocol (MCP) server for WhatsApp.

With this you can search and read your personal Whatsapp messages (including images, videos, documents, and audio messages), search your contacts and send messages to either individuals or groups. You can also send media files including images, videos, documents, and audio messages.

It connects to your **personal WhatsApp account** directly via the Whatsapp web multidevice API (using the [whatsmeow](https://github.com/tulir/whatsmeow) library). All your messages are stored locally in a SQLite database and only sent to an LLM (such as Claude) when the agent accesses them through tools (which you control).

Here's an example of what you can do when it's connected to Claude.

![WhatsApp MCP](./example-use.png)

> To get updates on this and other projects I work on [enter your email here](https://docs.google.com/forms/d/1rTF9wMBTN0vPfzWuQa2BjfGKdKIpTbyeKxhPMcEzgyI/preview)

> *Caution:* as with many MCP servers, the WhatsApp MCP is subject to [the lethal trifecta](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/). This means that project injection could lead to private data exfiltration.

---

## This fork: fail-closed send allowlist

Upstream lets an agent message **anyone in your contacts**, with no gate, no audit
trail and no kill switch. This fork adds an explicit allowlist in front of every
outbound action. Nothing is allowed by default.

Every send is keyed on the **exact WhatsApp JID** and on the **capability** being used
(`text`, `file`, `audio`). A display name can never authorise a send — names collide and
are attacker-controlled.

```
$ python allowlist.py allow 15550100001@s.whatsapp.net --caps text --label Alice
resolved: 15550100001@s.whatsapp.net  kind=person  label=Alice  caps=text

$ python allowlist.py check 15550100001@s.whatsapp.net --capability file
Refused: Alice may receive [text] but not 'file'.
To permit this, run: python allowlist.py allow 15550100001@s.whatsapp.net --caps file
```

### Safety properties

- **Default deny.** A missing, empty, unreadable, corrupt or wrong-version allowlist
  refuses **every** send.
- **Per-capability grants.** `text`, `file` and `audio` are granted independently, so a
  contact can be reachable by text while attachments stay blocked.
- **The capability is derived from the payload, never taken on trust.** A `text` grant
  cannot carry a file, and a `file` grant cannot carry a `.ogg` — which the bridge would
  deliver as a PTT voice note. Both gates compute it with the same rule
  (`media_capability` / `mediaCapability`); a caller may restate it but not contradict it.
- **The gate's own state is unsendable.** A media path inside the allowlist directory is
  refused, so `send_file` cannot exfiltrate the allowlist or the audit log.
- **Exact-JID matching.** Bare phone numbers are normalised (`+1 555 010 0001` →
  `15550100001@s.whatsapp.net`), device suffixes (`user:12@…`) are stripped so they
  cannot dodge an entry, and `@c.us` folds into `@s.whatsapp.net`.
- **Duplicates narrow, never widen.** Two entries for one JID intersect.
- **Unknown capability names grant nothing** (fail closed, not open).
- **Enforced twice.** In the Python MCP server *and* in the Go bridge, because the bridge
  is a plain HTTP API anything local can call.
- **Revocation is immediate.** The file is re-read on every send; nothing is cached.
- **Corrupt files are never silently overwritten** — `allow` refuses until you fix or
  delete it by hand.
- **Refusals tell you how to fix them**, printing the exact command to copy-paste.

### Additional hardening in this fork

- **The bridge binds to `127.0.0.1` only.** Upstream bound `:8080` (`0.0.0.0`), meaning
  any host on your LAN could POST `/api/send` and message your contacts as you. This was a
  real remote-send hole; it is closed here.
- **Audit log.** Every attempt, allowed or refused, is appended to
  `~/.config/whatsapp-mcp/send-audit.jsonl` as JSONL (`ts`, `source`, `requested`, `jid`,
  `label`, `capability`, `decision`, `allowed`, `media_path`, `reason`). The file is
  `0600` inside a `0700` directory because it contains raw recipients, and `source`
  distinguishes an MCP-layer record from a bridge-layer one. Audit failures never change
  a decision.
- **Kill switch.** `WHATSAPP_MCP_SEND_DISABLED=1` refuses everything regardless of the
  allowlist. This is **per-process**: the MCP server and the bridge each read their own
  environment, so set it for both if you want both stopped.
- **Dry-run.** `WHATSAPP_MCP_SEND_DRY_RUN=1` resolves and reports the would-be target and
  sends nothing.

### Managing the allowlist

```
python allowlist.py path                        # which file is in effect
python allowlist.py list [--json]               # what may be sent to
python allowlist.py allow <jid|phone|name> --caps text,file,audio --label "..."
python allowlist.py unallow <jid|label>          # works offline
python allowlist.py check <recipient> --capability text
```

`allow` resolves a chat *name* against the local `messages.db` as a convenience, but
refuses on ambiguity and prints the exact JID commands to re-run. `unallow` resolves
against the stored entries first, so revocation works with the database absent.

Exit codes: `0` ok · `1` invalid `--caps` value · `2` usage error, ambiguous match, or
not found · `3` refused (`check` also reports an unusable allowlist as `3`) · `4`
allowlist unusable (`list` / `allow` / `unallow`).

### Configuration

| Variable | Default | Purpose |
|---|---|---|
| `WHATSAPP_MCP_ALLOWLIST` | `~/.config/whatsapp-mcp/send-allowlist.json` | allowlist path |
| `WHATSAPP_MCP_AUDIT_LOG` | `~/.config/whatsapp-mcp/send-audit.jsonl` | audit path |
| `WHATSAPP_MCP_SEND_DISABLED` | unset | `1` blocks all sends |
| `WHATSAPP_MCP_SEND_DRY_RUN` | unset | `1` reports without sending |

Allowlist format (`version: 1`):

```json
{
  "version": 1,
  "updated": "2026-11-12T00:00:00+00:00",
  "entries": [
    { "jid": "15550100001@s.whatsapp.net", "label": "Alice",
      "allow": ["text"], "added": "2026-11-12T00:00:00+00:00" },
    { "jid": "120363000000000000@g.us", "label": "Test Group",
      "allow": ["text"], "added": "2026-11-12T00:00:00+00:00" }
  ]
}
```

### Tests

```
cd whatsapp-mcp-server && uv run --with pytest --python 3.12 \
    python -m pytest test_allowlist.py test_send_paths.py -q    # 91 tests
cd whatsapp-bridge   && go test ./...                           # 38 tests
```

`test_allowlist.py` covers the decision function: normalisation, every fail-closed branch,
capability separation, duplicate-narrowing, kill switch, dry-run and audit behaviour.
`test_send_paths.py` covers the *wiring* — it monkeypatches `requests.post` and asserts
that a refusal means no HTTP call at all, and that an allowed send carries the derived
capability. The Go suite includes `httptest` cases against the real `/api/send` handler.
Both exist because a review showed the gate could be deleted from a sender while the
rest of the suite stayed green.

### Known limitations

- **The allowlist constrains *who*, not *what*.** `send_file` will upload any readable
  path the process can open (the allowlist directory itself is blocked, but nothing else
  is restricted). A prompt-injected agent holding a `file` grant can therefore send
  documents it finds on disk. Grant `file` sparingly, and run the bridge as a user that
  cannot read what you would not send.
- **Recipient-only matching.** An allowed recipient is allowed *everything* granted to
  them, with no per-message content policy, size cap, or approval step.
- No outbound rate limiting (deliberate — it adds state and failure modes; add it if you
  need it).

> Still true, and still your problem: sending is irreversible and unrecoverable. The
> allowlist narrows *who* an agent can reach — it cannot stop a message that was allowed
> from being wrong, so review what you enable.

---

## Installation

### Prerequisites

- Go
- Python 3.11+
- Anthropic Claude Desktop app (or Cursor)
- UV (Python package manager), install with `curl -LsSf https://astral.sh/uv/install.sh | sh`
- FFmpeg (_optional_) - Only needed for audio messages. If you want to send audio files as playable WhatsApp voice messages, they must be in `.ogg` Opus format. With FFmpeg installed, the MCP server will automatically convert non-Opus audio files. Without FFmpeg, you can still send raw audio files using the `send_file` tool.

### Steps

1. **Clone this repository**

   ```bash
   git clone https://github.com/lharries/whatsapp-mcp.git
   cd whatsapp-mcp
   ```

2. **Run the WhatsApp bridge**

   Navigate to the whatsapp-bridge directory and run the Go application:

   ```bash
   cd whatsapp-bridge
   go run main.go
   ```

   The first time you run it, you will be prompted to scan a QR code. Scan the QR code with your WhatsApp mobile app to authenticate.

   After approximately 20 days, you will might need to re-authenticate.

3. **Connect to the MCP server**

   Copy the below json with the appropriate {{PATH}} values:

   ```json
   {
     "mcpServers": {
       "whatsapp": {
         "command": "{{PATH_TO_UV}}", // Run `which uv` and place the output here
         "args": [
           "--directory",
           "{{PATH_TO_SRC}}/whatsapp-mcp/whatsapp-mcp-server", // cd into the repo, run `pwd` and enter the output here + "/whatsapp-mcp-server"
           "run",
           "main.py"
         ]
       }
     }
   }
   ```

   For **Claude**, save this as `claude_desktop_config.json` in your Claude Desktop configuration directory at:

   ```
   ~/Library/Application Support/Claude/claude_desktop_config.json
   ```

   For **Cursor**, save this as `mcp.json` in your Cursor configuration directory at:

   ```
   ~/.cursor/mcp.json
   ```

4. **Restart Claude Desktop / Cursor**

   Open Claude Desktop and you should now see WhatsApp as an available integration.

   Or restart Cursor.

### Windows Compatibility

If you're running this project on Windows, be aware that `go-sqlite3` requires **CGO to be enabled** in order to compile and work properly. By default, **CGO is disabled on Windows**, so you need to explicitly enable it and have a C compiler installed.

#### Steps to get it working:

1. **Install a C compiler**  
   We recommend using [MSYS2](https://www.msys2.org/) to install a C compiler for Windows. After installing MSYS2, make sure to add the `ucrt64\bin` folder to your `PATH`.  
   → A step-by-step guide is available [here](https://code.visualstudio.com/docs/cpp/config-mingw).

2. **Enable CGO and run the app**

   ```bash
   cd whatsapp-bridge
   go env -w CGO_ENABLED=1
   go run main.go
   ```

Without this setup, you'll likely run into errors like:

> `Binary was compiled with 'CGO_ENABLED=0', go-sqlite3 requires cgo to work.`

## Architecture Overview

This application consists of two main components:

1. **Go WhatsApp Bridge** (`whatsapp-bridge/`): A Go application that connects to WhatsApp's web API, handles authentication via QR code, and stores message history in SQLite. It serves as the bridge between WhatsApp and the MCP server.

2. **Python MCP Server** (`whatsapp-mcp-server/`): A Python server implementing the Model Context Protocol (MCP), which provides standardized tools for Claude to interact with WhatsApp data and send/receive messages.

### Data Storage

- All message history is stored in a SQLite database within the `whatsapp-bridge/store/` directory
- The database maintains tables for chats and messages
- Messages are indexed for efficient searching and retrieval

## Usage

Once connected, you can interact with your WhatsApp contacts through Claude, leveraging Claude's AI capabilities in your WhatsApp conversations.

### MCP Tools

Claude can access the following tools to interact with WhatsApp:

- **search_contacts**: Search for contacts by name or phone number
- **list_messages**: Retrieve messages with optional filters and context
- **list_chats**: List available chats with metadata
- **get_chat**: Get information about a specific chat
- **get_direct_chat_by_contact**: Find a direct chat with a specific contact
- **get_contact_chats**: List all chats involving a specific contact
- **get_last_interaction**: Get the most recent message with a contact
- **get_message_context**: Retrieve context around a specific message
- **send_message**: Send a WhatsApp message to a specified phone number or group JID
- **send_file**: Send a file (image, video, raw audio, document) to a specified recipient
- **send_audio_message**: Send an audio file as a WhatsApp voice message (requires the file to be an .ogg opus file or ffmpeg must be installed)
- **download_media**: Download media from a WhatsApp message and get the local file path

### Media Handling Features

The MCP server supports both sending and receiving various media types:

#### Media Sending

You can send various media types to your WhatsApp contacts:

- **Images, Videos, Documents**: Use the `send_file` tool to share any supported media type.
- **Voice Messages**: Use the `send_audio_message` tool to send audio files as playable WhatsApp voice messages.
  - For optimal compatibility, audio files should be in `.ogg` Opus format.
  - With FFmpeg installed, the system will automatically convert other audio formats (MP3, WAV, etc.) to the required format.
  - Without FFmpeg, you can still send raw audio files using the `send_file` tool, but they won't appear as playable voice messages.

#### Media Downloading

By default, just the metadata of the media is stored in the local database. The message will indicate that media was sent. To access this media you need to use the download_media tool which takes the `message_id` and `chat_jid` (which are shown when printing messages containing the meda), this downloads the media and then returns the file path which can be then opened or passed to another tool.

## Technical Details

1. Claude sends requests to the Python MCP server
2. The MCP server queries the Go bridge for WhatsApp data or directly to the SQLite database
3. The Go accesses the WhatsApp API and keeps the SQLite database up to date
4. Data flows back through the chain to Claude
5. When sending messages, the request flows from Claude through the MCP server to the Go bridge and to WhatsApp

## Troubleshooting

- If you encounter permission issues when running uv, you may need to add it to your PATH or use the full path to the executable.
- Make sure both the Go application and the Python server are running for the integration to work properly.

### Authentication Issues

- **QR Code Not Displaying**: If the QR code doesn't appear, try restarting the authentication script. If issues persist, check if your terminal supports displaying QR codes.
- **WhatsApp Already Logged In**: If your session is already active, the Go bridge will automatically reconnect without showing a QR code.
- **Device Limit Reached**: WhatsApp limits the number of linked devices. If you reach this limit, you'll need to remove an existing device from WhatsApp on your phone (Settings > Linked Devices).
- **No Messages Loading**: After initial authentication, it can take several minutes for your message history to load, especially if you have many chats.
- **WhatsApp Out of Sync**: If your WhatsApp messages get out of sync with the bridge, delete both database files (`whatsapp-bridge/store/messages.db` and `whatsapp-bridge/store/whatsapp.db`) and restart the bridge to re-authenticate.

For additional Claude Desktop integration troubleshooting, see the [MCP documentation](https://modelcontextprotocol.io/quickstart/server#claude-for-desktop-integration-issues). The documentation includes helpful tips for checking logs and resolving common issues.
