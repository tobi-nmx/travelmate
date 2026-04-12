# Contributing a new portal handler

Thank you for contributing to magic.login! This guide explains how to capture
a debug log from an unknown captive portal and use it to generate a YAML handler.

---

## When is a YAML handler needed?

The built-in generic handler already handles most simple portals automatically
(single form, checkbox, basic username/password). A YAML handler is only needed
when the generic handler fails, for example:

- The portal requires multiple sequential form submissions and success is
  mis-detected early (false positive on "Welcome" text, etc.)
- Specific fields must be cleared or injected between steps
- Steps must be conditionally skipped based on response content (`only_if`)
- The final login POST goes to a different host than the portal page

If the generic handler already works reliably, no YAML is needed.

---

## Step 1 — Capture a debug log

Connect your device directly to the hotspot (phone, tablet, laptop — anything
with Python 3 installed).

> ⚠️ **Important:** Do NOT interact with the captive portal in your browser
> before running the script. If you accept the portal manually first, the script
> will just report "already connected" and produce no useful debug output.
> If this happens, disconnect from the WiFi, reconnect, and run the script
> immediately — before opening any browser.

**Install dependencies (once):**

On Android with [Termux](https://termux.dev):
```sh
pkg install python
pip install --break-system-packages pyyaml
```

On any other system with Python 3:
```sh
pip install pyyaml
```

**Run the script in debug mode:**
```sh
python magic.login --debug --no-bind
```

- `--debug` writes a full session log and HTML dumps to `/tmp/captive-debug/`
  (or `./captive-debug/` on Termux, where `/tmp` is not available)
- `--no-bind` disables OpenWrt-specific interface binding (required outside OpenWrt)

**After the run, collect the debug files:**

On OpenWrt: `/tmp/captive-debug/`  
On Termux: `./captive-debug/` (in the directory where you ran the script)

```
captive-debug/
  session.log          ← timestamped log of all requests and responses
  step_01_*.html       ← raw HTML of each page encountered
  step_02_*.html
  ...
```

---

## Step 2 — Generate a YAML handler using AI

Open a new chat with an AI assistant (Claude, ChatGPT, etc.) and paste the
following prompt, followed by the contents of `session.log`:

---

```
You are an expert at analyzing captive portal login flows and writing YAML handler
files for magic.login, a universal captive portal auto-login script for OpenWrt/Travelmate.

Reference documentation: https://github.com/tobi-nmx/travelmate/blob/main/README.md

## Your task

Given a debug log from `magic.login --debug --no-bind`, analyze the login flow and
write a YAML handler file for magic.d/.

## What to look for in the log

- `[detect] Portal redirect:` — the initial portal URL (use for match patterns)
- `[Generic] Form:` lines — each is one step: note the action URL and field names
- `[Generic] Response URL:` — where each step redirects to
- `[Generic] Connectivity confirmed` — marks which step actually completed the login
- Field names containing TOKEN, SESSION, KEY, FREEKEYWIFI → need `only_if`
- Fields named link-orig, dst, redirect → usually need `clear_fields`
- `type=checkbox` fields → add `check_boxes: true`
- If the final POST goes to a different host than the portal → add `only_if_action`

## What to ask for if missing

If the debug log does not contain enough detail for a step (i.e. you see a form
submission but cannot verify the field names or action URL), ask the user to provide
the corresponding step_XX_*.html file from /tmp/captive-debug/.

Only ask for files that are actually needed to write a correct handler — do not ask
for all files upfront.

## Output format

Write a complete, ready-to-use YAML file following this structure:

# <portal name> captive portal handler
# ──────────────────────────────────────
# Brief description of the portal and its login flow.
# Number of login steps: <N>
# SSID: <if known>
# Portal URL: <detected URL>

name: <portal name>
priority: 30

match:
  - <pattern from portal URL>

retry_delays: [1, 2, 3, 5, 5]

steps:
  - label: <descriptive name>
    action: from_form
    fields: from_form
    # add check_boxes, clear_fields, only_if, only_if_action as needed

Add a comment above each non-obvious option explaining why it is needed.
Do not add options that are not required — keep the YAML minimal.

## Important rules

- Only generate a YAML handler if the generic handler could NOT complete the login
  on its own, or if the flow requires only_if / only_if_action logic to be reliable.
- If the generic handler already handled the portal successfully with no special
  logic needed, say so and explain that no YAML is required.
- Never guess field names or action URLs — if uncertain, ask for the HTML file.
```

---

The AI will analyze the log and either write a YAML handler or tell you that no
handler is needed. If it asks for a specific `step_XX_*.html` file, paste its
contents into the chat.

---

## Step 3 — Test the handler

Copy the generated YAML file to `magic.d/` on your OpenWrt router:

```sh
scp magic.d/myportal.yaml root@192.168.1.1:/etc/travelmate/magic.d/
```

Then test it:
```sh
ssh root@192.168.1.1 /etc/travelmate/magic.login --debug --force
```

- `--force` skips the fast online pre-check and always runs the full login flow
- `--debug` lets you verify that the new YAML handler is being used

Look for `[dispatch] Matched YAML handler:` in the output — that confirms the new
handler was picked up instead of the generic fallback. Then verify that the script
reports `[*] Login successful` and that internet access actually works.

---

## Step 4 — Share your handler

There are two ways to contribute, depending on your comfort level:

### Option A — Open a GitHub Issue (easiest)

If pull requests feel daunting, just [open a new issue](../../issues/new) with:

- The portal name and URL
- Which SSIDs or regions it applies to
- Whether credentials are required
- The number of login steps (visible in the YAML header comment)
- The generated YAML file pasted into the issue

Someone will review it and add it to the repository.

### Option B — Submit a pull request

1. Fork the repository
2. Add the YAML file to `magic.d/`
3. Open a pull request with the same information as above

Please do **not** modify `magic.login` itself for portal-specific logic —
all portal handlers belong in `magic.d/`.

---

## Going deeper

For the full YAML step reference, Python plugin API, and an explanation of how
the dispatcher and generic handler work internally, see [INTERNALS.md](INTERNALS.md).
