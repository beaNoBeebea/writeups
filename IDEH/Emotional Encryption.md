# Emotional Encryption - IDEH 2026 Writeup

**Category:** [[Crypto]]   
**Flag:** `IDEH{3m0j1s_Ar3_Th3_N3w_H3xxx_H4H4}`

## I. Overview

> We intercepted a private communication from Nemesis. He seems to have developed his own language to bypass our keyword filters.
> 
> At first glance, it looks like a meaningless sequence of emojis. But we know Nemesis is a logical being.
> 
> He always starts from an origin point, a Smiling Face with Horns (😈), and transforms his thoughts using a simple 3 digits numeric key .
> 
> Decipher this dialect to uncover what he is hiding

We are provided with a file `message_emoji.txt` containing the following emoji sequence:

```txt
🚮🚳🚲🚯🚜🛤🚊🛧🚍🛦🚤🚸🚶🚥🛤🚸🛃🚏🛤🚸🚩🛤🚠🚸🚯🛤🚟🚟🚟🚸🚯🛣🚯🛣🚚
```

## II. Initial Observations

Key hints are given by the challenge:
1. **Fixed origin point:** All transformations start from the Unicode codepoint of "😈".
2. **3-digit numeric key:** Implies a small integer key space (100-999).
3. **Logical transformation:** Likely arithmetic or bitwise.
4. **Emoji-based encoding:** Emojis are Unicode codepoints, meaning we can treat them as integers.

Given this, the problem reduces to reversing a numeric transformation applied to Unicode codepoints.

## III. Vulnerability Analysis & Hypothesis

### Converting Emojis to Codepoints

We first convert each emoji into its Unicode integer representation so we can operate on numeric values.

```python
message = "🚮🚳🚲🚯🚜🛤🚊🛧🚍🛦🚤🚸🚶🚥🛤🚸🛃🚏🛤🚸🚩🛤🚠🚸🚯🛤🚟🚟🚟🚸🚯🛣🚯🛣🚚"

codepoints = [ord(e) for e in message]
origin = ord("😈")
```

To normalize the data, we compute the **offset from the origin**:

```python
offsets = [cp - origin for cp in codepoints]
# [166, 171, 170, 167, 148, 220, 130, 223, 133, 222, 156, 176, 174, 157, 220, 176, 187, 135, 220, 176, 161, 220, 152, 176, 167, 220, 151, 151, 151, 176, 167, 219, 167, 219, 146]
```

Interesting enough is the resulting offsets fall within a range compatible with byte-wise operations.

### Hypothesis 1: Linear Offset Cipher

The simplest cipher would be:

```
ciphertext = plaintext + key + origin
```

To decrypt:

```
plaintext = ciphertext - origin - key
```

And I know the flag starts with `IDEH{`

So let's test this theory:

```python
ciphertext = ord("🚮")
plaintext = ord("I")
origin = ord("😈")

key = ciphertext - origin - plaintext
print(key)
```

This returns 93.
And for the second character

```python
ciphertext = ord("🚳")
plaintext = ord("D")
origin = ord("😈")

key = ciphertext - origin - plaintext
print(key)
```

This returns 103.

This gives us two different values for the key. So this won't work.

### Hypothesis 2:  XOR-based Cipher

XOR properties:

- Self-inverse: `A ^ B ^ B = A`
- Operates cleanly on bytes

**Assumed encryption model:**

```
offset = plaintext_byte ^ key
emoji_codepoint = origin + offset
```

Thus, decryption becomes:

```
plaintext_byte = (emoji_codepoint - origin) ^ key
```

Since the key is 3 digits, the search space is small: `100–999`.

XOR operates on bytes, so we reduce the key modulo 256.

```python
for key in range(100, 1000):
	k = key % 256   # XOR works on bytes
	
	try:
		# XOR decrypt
		pt = bytes([b ^ k for b in offsets])
		
		# check if it starts with flag format
		if pt.startswith(b"IDEH{"):
			print(f"Found key: {key}")
			print(f"Key % 256: {k}")
			print(f"Flag: {pt.decode()}")
			break
	except:
		# skip if decryption produces invalid bytes
		continue
```

#### Output:

```
Found key: 239
Key % 256: 239
Flag: IDEH{3m0j1s_Ar3_Th3_N3w_H3xxx_H4H4}
```

### Understanding the Cipher

The encryption logic used by Nemesis can be summarized as:

```python
key = 239
origin = ord("😈")

for byte in plaintext:
    offset = byte ^ key
    emoji = chr(origin + offset)
```

## Conclusion

This challenge demonstrates how Unicode can be abused as a **transport layer** for classical cryptography. By disguising byte-level XOR encryption as emoji transformations, Nemesis effectively bypassed naive content filters. Despite that, it still not very robust.

This highlights why obscurity in encoding does not equate to cryptographic security.


[[IDEH2026]]