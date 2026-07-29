# MediatorVpnService — Project Structure & Working Report

## 1. What This Project Is

This is an **Android local VPN POC (proof-of-concept)** app. It uses Android's `VpnService` API to create a virtual network interface (TUN) on the device. All app traffic is routed through this tunnel into the app's own process, where raw IP packets are parsed, logged, and then **re-forwarded to their real destination** using ordinary sockets (`Socket`/`DatagramSocket`) that bypass the tunnel via `protect()`. Replies from the real destination are translated back into IP packets and written back into the tunnel so the originating app (a `WebView` in this case) gets a normal response.

Alongside the packet-forwarding engine, the project has a **live dashboard** (MVVM: Repository → ViewModel → Activity/RecyclerView) that mirrors every important event and running statistic to the UI in real time.

---

## 2. High-Level Architecture

```
 VpnTestActivity (UI)
   │  1. Requests VPN consent (VpnService.prepare)
   │  2. Starts MediatorVpnService
   │  3. Loads a URL in a WebView (traffic source)
   ▼
 MediatorVpnService (extends android.net.VpnService)
   │  - Builds & establishes the TUN interface
   │  - Runs a background thread reading raw packets from TUN
   │  - Parses IPv4 header, classifies protocol (TCP/UDP/ICMP/other)
   │  - Delegates to TcpForwarder / UdpForwarder
   │  - Publishes every event/stat to VpnEventRepository
   ▼
 TcpForwarder / UdpForwarder
   │  - Maintain per-connection session maps (keyed by src:port->dst:port)
   │  - Open real Socket/DatagramSocket, vpnService.protect() them
   │  - Relay client → real server (write out)
   │  - Relay real server → client (build IP/TCP/UDP packets, write into TUN)
   ▼
 PacketUtils (static helpers)
   │  - Builds raw IPv4 / TCP / UDP headers
   │  - Computes IP & TCP checksums
   ▼
 VpnEventRepository (singleton, LiveData-based)
   │  - latestEvent: stream of log lines (VpnEvent)
   │  - stats: aggregated counters/status (VpnStats, immutable "with..." updates)
   ▼
 VpnDashboardViewModel  →  VpnTestActivity observers  →  VpnEventAdapter (RecyclerView)
   (renders live status fields + a scrolling event console)
```

---

## 3. File-by-File Breakdown

### 3.1 `MediatorVpnService.java` — the core VPN service

Extends `VpnService`; this is the heart of the app.

| Method | Responsibility |
|---|---|
| `onCreate()` | Basic lifecycle log. |
| `onStartCommand()` | Entry point when the service starts. Sets dashboard status to "Starting", calls `startForeground()` (required for VPN services), then calls `establishVpn()` followed by `startPacketReadingLoop()`. Returns `START_STICKY` so Android restarts the service if it's killed. |
| `establishVpn()` | Uses `VpnService.Builder` to configure the virtual interface: assigns IP `10.0.0.2/24`, routes **all** traffic (`0.0.0.0/0`) through the tunnel, sets DNS to `8.8.8.8`, MTU 1500, and excludes the app itself from the tunnel (`addDisallowedApplication`) to avoid a routing loop. Calls `builder.establish()` to actually create the TUN fd. On success it opens a `FileOutputStream` on the tunnel fd and constructs `UdpForwarder`/`TcpForwarder`, wiring them to the same output stream and a shared lock (`tunWriteLock`) so writes from multiple threads don't interleave. Reports status to the dashboard at every step (Established/Failed). |
| `startPacketReadingLoop()` | Spawns a dedicated thread (`VpnPacketReaderThread`) that continuously calls `in.read(buffer)` on a `FileInputStream` wrapping the TUN fd — this blocks until the OS hands it an outbound packet from any app. Each packet read is passed to `handlePacket()`. Loop exits when `isRunning` is set false or an `IOException` occurs. |
| `handlePacket(byte[], int)` | The packet parser/dispatcher — called once per raw IP packet: <br>1. Rejects packets under 20 bytes (too short for an IPv4 header).<br>2. Reads IP version (top nibble of byte 0); skips non-IPv4 (e.g., IPv6) packets, logging + counting them via the dashboard.<br>3. Reads the protocol byte (offset 9) to classify TCP(6)/UDP(17)/ICMP(1)/other.<br>4. Extracts source/destination IP (bytes 12–15, 16–19).<br>5. Computes IP header length from the IHL nibble, then (for TCP/UDP) reads source/destination ports from just after the IP header.<br>6. Looks up/creates a `ConnectionInfo` entry in `activeConnections` keyed by `"srcIp:srcPort->dstIp:dstPort"`, updating its byte counters — this is essentially a lightweight connection tracker (not yet surfaced in the UI, but structured for future use).<br>7. Logs the packet and mirrors it into the dashboard (`recordPacket`, `logEvent`).<br>8. **Relays** the packet: TCP → `tcpForwarder.handlePacket(...)`, UDP → `udpForwarder.handlePacket(...)`. ICMP/other are logged only, not forwarded. |
| `ipBytesToString()` | Converts 4 raw bytes into dotted-decimal IP string. |
| `buildNotification()` | Builds the mandatory foreground-service notification (creates a notification channel on API 26+), tapping it opens `VpnTestActivity`. |
| `onDestroy()` / `stopVpn()` | Cleans up: stops the reading loop, shuts down both forwarders (closing all live sockets), closes the TUN output stream and the `ParcelFileDescriptor`, and updates dashboard status to Stopped/Closed. |
| `onRevoke()` | Called by Android if the user revokes VPN permission from system settings; logs a warning and stops the service. |

### 3.2 `PacketUtils.java` — raw packet construction toolkit

Static utility class (no state) used by both forwarders to build synthetic reply packets.

| Method | Responsibility |
|---|---|
| `checksum(data, offset, length)` | Generic Internet checksum (RFC 1071 one's-complement sum) used for both IP and TCP/UDP checksums. |
| `writeIPv4Header(buf, totalLength, protocol, srcIp, dstIp)` | Writes a fixed 20-byte IPv4 header (version/IHL, TTL=64, DF flag set, protocol number, src/dst IP) directly into a `ByteBuffer`, then computes and patches in the correct header checksum. |
| `writeUdpHeader(buf, srcPort, dstPort, udpLength)` | Writes an 8-byte UDP header; checksum is left as 0 (optional for IPv4). |
| `writeTcpHeader(buf, srcPort, dstPort, seq, ack, flags, window)` | Writes a 20-byte TCP header (no options), leaving the checksum field as a placeholder to be filled later. |
| `fixTcpChecksum(packet, ipHeaderStart, tcpHeaderStart, tcpSegmentLength, srcIp, dstIp)` | Builds the TCP pseudo-header (src/dst IP + protocol + segment length) prepended to the actual TCP segment, computes the checksum over that combined buffer, and patches it into the real packet at the correct offset. |
| Constants | TCP flag bits (`FIN/SYN/RST/PSH/ACK`) and protocol numbers (`PROTO_TCP=6`, `PROTO_UDP=17`). |

### 3.3 `TcpForwarder.java` — user-space TCP proxy

Implements a **minimal TCP state machine** so the app can pretend to be the real TCP endpoint to the client while a genuine `Socket` talks to the actual destination.

| Method | Responsibility |
|---|---|
| `handlePacket(...)` | Main dispatcher per TCP segment, driven by flags: <br>• **New SYN** (no existing/duplicate session) → closes any stale session, calls `startNewSession()`.<br>• **No session found + not RST** → treats as an unknown/stale connection and sends a RST back.<br>• **RST received** → tears down the session.<br>• **SYN-ACK'd by client** (state `SYN_RCVD` + ACK flag) → transitions to `ESTABLISHED` and starts the thread that reads from the real socket.<br>• **Payload present + ESTABLISHED** → writes the payload to the real socket's `OutputStream`, advances the expected client sequence number, and sends an ACK back to the client. On write failure, sends RST and closes the session.<br>• **FIN received** → advances sequence, ACKs, half-closes the real socket's output, and marks the session `CLOSING`. |
| `startNewSession(...)` | Creates a `TcpSession`, records the client's ISN (+1 for the SYN's sequence consumption), generates a random device-side ISN, sets state `SYN_RCVD`, and stores it in the `sessions` map. On a **separate thread**, opens a real `Socket`, calls `vpnService.protect(socket)` (critical — prevents this outbound connection from re-entering the tunnel and causing an infinite loop), connects to the true destination, then sends a synthetic **SYN-ACK** back to the client via `sendSynAck()`. Connection failure sends a RST and removes the pending session. |
| `sendSynAck()` / `sendAck()` | Build and write synthetic TCP control packets to the client through `writeTcpPacket()`. |
| `sendDataToClient(session, data, len)` | Called by the session's real-socket reader thread whenever data arrives from the real server; wraps it as a TCP data segment (ACK+PSH) addressed back to the client and advances the device-side sequence number. |
| `sendFinToClient(session)` | Sent when the real socket hits EOF, telling the client the server side is done sending. |
| `sendRst(...)` | Sends a TCP RST to abort/reject a connection. |
| `writeTcpPacket(...)` | Central packet builder: assembles IPv4 header + TCP header (+ optional payload) via `PacketUtils`, fixes the TCP checksum, then writes the full packet into the TUN device under `tunWriteLock` (shared with the UDP forwarder to serialize all writes to the single tunnel fd). |
| `closeSession(...)` | Removes the session from the map, marks it `CLOSED`, and closes the real socket. |
| `shutdown()` | Closes every active session (called when the VPN service stops). |
| `TcpSession` (inner class) | Holds per-connection state: IPs/ports, sequence numbers (`clientNextSeq`, `deviceSeq`), the real `Socket`/streams, and connection `State` (`SYN_RCVD → ESTABLISHED → CLOSING/CLOSED`). Its `startRealSocketReaderThread()` spins up a daemon thread that continuously reads from the real socket's `InputStream` and forwards each chunk to the client via `sendDataToClient`, sending a FIN when the stream ends. |

### 3.4 `UdpForwarder.java` — user-space UDP proxy

Simpler than TCP since UDP is connectionless, but still needs per-flow session tracking to route replies back correctly.

| Method | Responsibility |
|---|---|
| Constructor | Starts a scheduled executor that runs `reapIdleSessions()` every 30 seconds to garbage-collect stale sessions. |
| `handlePacket(...)` | Extracts the UDP payload (offset = IP header + 8-byte UDP header), looks up an existing `Session` by `"src:port->dst:port"` key or creates one via `createSession()`, then sends the payload out through the session's real `DatagramSocket` to the actual destination and refreshes its idle timer. |
| `createSession(...)` | Opens a real `DatagramSocket`, calls `vpnService.protect(socket)` (same anti-loop safeguard as TCP), resolves the destination `InetAddress`, wraps it all in a `Session`, and starts a listener thread for replies. |
| `startReplyListener(key, session)` | Daemon thread that blocks on `socket.receive()`; for every datagram received from the real server, it touches the session (resets idle timer) and calls `writeUdpReplyToTun()`. Loop ends when the socket is closed. |
| `writeUdpReplyToTun(...)` | Builds a synthetic reply packet: IPv4 header (swapped so it appears to come from the original destination back to the original source) + UDP header + payload, via `PacketUtils`, then writes it into the TUN under `tunWriteLock`. |
| `reapIdleSessions()` | Iterates all sessions; any idle longer than `SESSION_IDLE_TIMEOUT_MS` (60s) gets closed. |
| `closeSession(...)` | Removes from the map and closes the socket. |
| `shutdown()` | Stops the cleanup executor and closes all sessions (called on VPN teardown). |
| `Session` (inner class) | Holds the real socket, destination address, original src/dst IP+port, and `lastActivity` timestamp (`touch()` updates it). |

### 3.5 `VpnTestActivity.java` — UI entry point

| Method | Responsibility |
|---|---|
| `onCreate()` | Inflates the layout, binds all dashboard views, wires up the event console `RecyclerView`, enables JavaScript in the `WebView`, sets the "Start VPN" button listener, and obtains the `VpnDashboardViewModel`. It **observes** `getLatestEvent()` (pushes new log rows into the adapter) and `getStats()` (updates every status/counter `TextView` whenever the aggregated stats object changes). |
| `bindDashboardViews()` | Looks up all the dashboard `TextView`s by ID. |
| `setupEventConsole()` | Configures the `RecyclerView`/`VpnEventAdapter` used as a scrolling log console. |
| `onNewEvent(event)` | Appends an event to the adapter and auto-scrolls to the newest entry. |
| `onStartVpnClicked()` | Calls `VpnService.prepare(this)`. If it returns a non-null `Intent`, the user hasn't granted consent yet, so it's launched via the `ActivityResultLauncher` (`vpnPermissionLauncher`); otherwise permission is already granted and `startVpnServiceAndLoadWebView()` runs immediately. |
| `vpnPermissionLauncher` (field) | Callback for the consent dialog result: on `RESULT_OK` proceeds to start the service; otherwise shows a toast and logs the denial. |
| `startVpnServiceAndLoadWebView()` | Starts `MediatorVpnService` as a foreground service (`startForegroundService` on API 26+) and loads the user-entered URL into the `WebView` — this WebView traffic is what actually flows through the tunnel. |
| `resolveTargetUrl()` | Reads the URL `EditText`, defaults to prepending `https://` if no scheme was given. |
| `updateStatus()` | Simple helper to log + update the top status `TextView`. |

### 3.6 Dashboard / MVVM Layer

**`VpnEvent.java`** — immutable data class for one log line: `message`, `Level` (SUCCESS/INFO/WARNING/ERROR), `Category` (GENERAL/TCP/UDP/ICMP/OTHER/IPV6_SKIPPED/ERROR), and a timestamp.

**`VpnStats.java`** — immutable snapshot of aggregate state (VPN/permission/interface/reader status strings, total/TCP/UDP/IPv6-skipped packet counts, and details of the last packet seen). Uses a **"withX()" copy pattern** — every mutation method (`withVpnStatus`, `withPacket`, `withIpv6Skipped`, etc.) returns a brand-new `VpnStats` instance rather than mutating in place, which is safe to publish via `LiveData` from background threads.

**`VpnEventRepository.java`** — app-wide singleton (`getInstance()`, double-checked locking) holding two `LiveData` streams:
- `latestEvent: MutableLiveData<VpnEvent>` — updated by `logEvent()`.
- `stats: MutableLiveData<VpnStats>` — updated by `setVpnStatus`, `setPermissionStatus`, `setInterfaceStatus`, `setReaderStatus`, `recordPacket`, and `recordIpv6Skipped`, each of which reads the current value and calls the matching immutable `withX()` method before `postValue()` (safe from any thread, including the packet-reader and forwarder threads).

**`VpnDashboardViewModel.java`** — thin `ViewModel` wrapper exposing the repository's two `LiveData` streams to the Activity, decoupling the UI from the singleton.

**`VpnEventAdapter.java`** — `RecyclerView.Adapter` backing the event console:
- Stores events in an `ArrayDeque` capped at `MAX_ENTRIES = 3000`; `addEvent()` evicts the oldest entry once the cap is hit (`removeFirst` + `notifyItemRemoved(0)`), then reports the newly inserted item.
- `onBindViewHolder()` snapshots the deque into an `ArrayList` per bind call (needed because `ArrayDeque` has no index access) and displays the message + formatted timestamp.
- `EventViewHolder.bind()` picks an icon/color based on category first (TCP/UDP/IPV6_SKIPPED/ERROR get dedicated icons), falling back to level-based icon/color (SUCCESS/WARNING/ERROR/INFO) for GENERAL/OTHER events.

**`ConnectionInfo.java`** — plain POJO tracking a single logical connection's metadata (IPs, ports, protocol, bytes sent/received, start/end time, RTT, uid). Currently populated by `MediatorVpnService.handlePacket()` into the `activeConnections` map but not yet displayed anywhere in the UI — it's scaffolding for a future "active connections" view.

---

## 4. End-to-End Data Flow (Example: HTTPS request from the WebView)

1. User taps **Start VPN** → `VpnTestActivity.onStartVpnClicked()` requests consent via `VpnService.prepare()`.
2. On consent, `startVpnServiceAndLoadWebView()` starts `MediatorVpnService` and loads a URL in the `WebView`.
3. `MediatorVpnService.onStartCommand()` → `establishVpn()` creates the TUN device and routes **all** device traffic through it; `startPacketReadingLoop()` begins reading raw packets.
4. The WebView's outbound TCP SYN packet is captured by the OS and delivered to the TUN fd → read by the packet-reader thread → `handlePacket()` parses it as TCP → `tcpForwarder.handlePacket()`.
5. `TcpForwarder` sees a fresh SYN, opens a real `Socket` to the destination (protected from the tunnel), and once connected, sends a synthetic **SYN-ACK** back into the tunnel — from the WebView's perspective, it just completed a normal TCP handshake with the real server.
6. As the WebView writes TLS/HTTP data, those packets flow into `TcpForwarder`, which forwards the raw bytes onto the real socket, and ACKs the client.
7. The real server's response arrives on the real socket's `InputStream`, read by the session's reader thread, wrapped into a synthetic TCP packet by `sendDataToClient()`, and written into the TUN — the WebView receives it exactly as if it came directly from the server.
8. Every step along the way calls `dashboard.logEvent(...)` / `dashboard.recordPacket(...)`, updating `VpnEventRepository`'s `LiveData`, which the `VpnDashboardViewModel` exposes and `VpnTestActivity`'s observers render live in the status fields and scrolling console.
9. On stop/destroy, `MediatorVpnService.stopVpn()` shuts down both forwarders (closing every real socket) and tears down the TUN interface.

---

## 5. Key Design Points Worth Noting

- **Loop prevention:** every outbound real socket (`TcpForwarder`'s `Socket`, `UdpForwarder`'s `DatagramSocket`) is passed through `vpnService.protect()`, which is what stops the proxy's own traffic from being re-captured by the very tunnel it created.
- **Single-writer discipline:** `tunWriteLock` is shared across the service and both forwarders so that concurrent threads (packet reader, TCP reply threads, UDP reply threads) never interleave partial writes to the TUN fd.
- **Immutable state publishing:** `VpnStats`'s copy-on-write pattern makes it safe to update dashboard state from arbitrary background threads without synchronization bugs, since `LiveData.postValue()` handles the main-thread dispatch.
- **ICMP/other protocols** are observed and logged but intentionally **not forwarded** — this is a TCP/UDP-only POC.
- **No IPv6 support** — IPv6 packets are detected and counted (`recordIpv6Skipped`) but dropped, since the whole header-parsing logic assumes IPv4.
- **`ConnectionInfo`/`activeConnections`** is currently write-only scaffolding — populated per packet but never read anywhere else, likely intended for a future "live connections" UI panel.
