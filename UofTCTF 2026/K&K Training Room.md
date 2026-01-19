# K&K Training Room - UofT CTF Writeup

**Category:** [[Misc]]    
**Flag:** `uoftctf{tr41n_h4rd_w1n_345y_a625e2acd5ed}`

## I. Challenge Overview

> Welcome to the K&K Training Room. Before every match, players must check in through the bot.
> 
> A successful check in grants the K&K role, opening access to team channels and match coordination.

The challenge provides a Discord bot interface where players should "check in" to receive the K&K role. This role should grant access to hidden channels where the flag must be stored.

We are provided with the bot's source code (`index.js`) and its environment configuration (`package.json`).


## II. Analysis

### 1. Discord Server Read-Only

Before going forward with any analysis, we have to recognize that the discord server is read-only for me as of this step. This means that any interaction with the bot would have to be done outside of this specific server.

### 2. The Authentication Logic

The bot relies on a specific configuration to identify admins:

```js
const CONFIG = {
ROLE_NAME: 'K&K',
ADMIN_NAME: 'admin',
WEBHOOK_NAME: 'K&K Announcer',
TARGET_GUILD_ID: '1455821434927579198',
};

const isAdmin = (message) => message.author.username === CONFIG.ADMIN_NAME;
```

The `isAdmin` function checks the `message.author.username`.

### 3. Identifying the Command Flow

The bot listens for `!webhook` command, which is intended to set up an announcer webhook - a webhook is a tool that allows external services to post messages to a channel using a unique URL -.

```js
client.on(Events.MessageCreate, async (message) => {
if (message.content !== '!webhook') return;
if (!isAdmin(message)) {
return message.reply(`Only \`${CONFIG.ADMIN_NAME}\` can set up the K&K announcer webhook.`);
}
// ...
// creates a webhook and replies with the URL
});
```

When I try to run this command from my own Discord account, the bot checks my username. Since my username is not `admin`, the `isAdmin` check fails, and I am denied access.

Changing my display as well will not help, only the username `admin` will do.

I have to find my way around this as gaining access to the `K&K Announcer` webhook is crucial to go forward.

### 4. Role Assignment Logic

The bot also handles interactions, specifically looking for a button click that triggers the role assignment:

```js
client.on(Events.InteractionCreate, async (interaction) => {
  if (!interaction.isButton() || interaction.customId !== 'checkin') return;
  
  // Fetch the target guild and K&K role
  const guild = client.guilds.cache.get(CONFIG.TARGET_GUILD_ID);
  // ...
  const role = guild.roles.cache.find(r => r.name === CONFIG.ROLE_NAME);
  // ...
  
  // Fetch the member and assign role
  let member = await guild.members.fetch(interaction.user.id);
  // ...
  await member.roles.add(role);
  // ...
  
  return interaction.reply({
    content: `Checked in at **${guild.name}**! Assigned **${role.name}**.`,
    flags: MessageFlags.Ephemeral,
  });
});
```

This function is supposed to give the role `K&K` to any user in the discord server who clicks on a certain button  with `custom_id` set to `checkin`.

This alludes to a certain role being accessible by the click of a button which could give us access to the hidden channels on the server.

So if we could force the bot to post such a button via its announcer webhook, we can gain access to the hidden channels.

So my checklist looks like the following:
1. Invite the K&K bot to an outside server where I can interact with it.
2. Trick the K&K bot into thinking that I am -or another entity of my creation- the "admin".
3. Somehow force the bot to post a button with `custom_id` set to `checkin`.


## III. Identifying the Vulnerabilities

This challenge exploits two distinct vulnerabilities that work together:
### Vulnerability 1: Authentication Bypass via Webhook Spoofing

The critical flaw in this challenge lies in how the bot verifies the role `admin`.   
The `isAdmin` function only checks if `message.author.username === 'admin'`, but it doesn't verify whether the message comes from an actual user or from a webhook.

Moreover, in Discord's API, when a message is sent through a webhook, the `message.author.username` is set to the **webhook's name**. This means that if I create a webhook named `admin` and send messages through that webhook, the bot will see `message.author.username` as `admin`. This way, the `isAdmin` check will pass!

This authentication bypass allows us to impersonate the admin and execute the `!webhook` command.

### Vulnerability 2: Unauthenticated Interaction Handling

A second crucial vulnerability lies in how the bot processes button interactions. The bot accepts any button click with `customId="checkin"` without verifying the source of the button or whether it was posted by a legitimate admin.

Due to a Discord API feature, application-owned webhooks can send messages containing interactive components like buttons. So, once we obtain the K&K Announcer webhook, we can craft our own message with a check-in button, and the bot will trust any interactions with it, thus assigning the K&K role to anyone who clicks, regardless of authorization.


## IV. Strategy & Exploitation

With the vulnerability identified, here's my simple attack plan:

### Step 1: Invite the Bot to a Controlled Server

This is the easiest step, as I only need to invite the bot to a server of my creation. This requires constructing an OAuth2 invite link using the bot's client ID (which can be obtained by enabling Discord Developer Mode and copying the bot's ID) and with permissions=8 to give the bot full administrator permissions.

The invite URL format:
```
https://discord.com/oauth2/authorize?client_id=BOT_ID&permissions=8&scope=bot
```

### Step 2: Trigger the `!webhook` Command

In my controlled server, in a channel, I created a webhook named `admin` and copied its URL.

Then, I used my spoofed webhook to send the `!webhook` command:

```bash
curl -H "Content-Type: application/json" \ -d '{"content":"!webhook"}' \ "WEBHOOK_URL_I_JUST_COPIED"
```

The K&K bot is already in my controlled server, and specifically in the channel I'm operating in. So the bot will accept this request (seeing `message.author.username` as `admin`) and respond with the **K&K Announcer webhook URL** for the target server. 

### Step 3: Post the Check-In Button

Using the K&K Announcer webhook obtained from the bot (basically impersonating the bot),  I sent a message with a button component:

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
  "K&K_ANNOUNCER_URL"
```

All I have to do then is click on the button to gain the role `K&K` in the original server.

### Step 4: Claim the Flag

Now that I have the `K&K` role assigned to myself, I have newfound access to channels that were previously hidden to me.

In the channel `#private-archives`, I found the flag in a message sent by the K&K bot.


## V. Prevention

The root cause of this vulnerability is the naive authentication check that trusts usernames without validating message sources.

### 1. Reject Webhook Messages

The simplest fix is to explicitly reject all webhook-originated messages:

```js
const isAdmin = (message) => {
  if (message.webhookId) return false; // Reject all webhook messages
  return message.author.username === CONFIG.ADMIN_NAME;
};
```

### 2. Use Discord's Permission System

A more robust approach uses Discord's built-in permissions:

```js
const isAdmin = (message) => {
  return message.member?.permissions.has(PermissionFlagsBits.Administrator);
};
```

### 3. Restrict Bot Installation

Disable the "Public Bot" option in the Discord Developer Portal to prevent unauthorized users from adding the bot to their own servers, which is a prerequisite for this attack (the server was read-only for me).

### 4. Validate Interaction Sources 

To prevent unauthorized button usage, validate that interactions come from expected sources: 

```js
client.on(Events.InteractionCreate, async (interaction) => { 
	if (!interaction.isButton() || interaction.customId!== 'checkin') return; 

	// Verify the message was sent by the bot itself, not a webhook 
	if (interaction.message.webhookId) { 
		return interaction.reply({ 
			content: 'Invalid check-in source.', 
			flags:MessageFlags.Ephemeral, 
		}); 
	}

	// ... rest of role assignment logic
}); 
```


[[UOFTCTF2026]]