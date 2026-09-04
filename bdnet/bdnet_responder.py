"""Demonware bdNet responder for BO2 Wii U.

Three protocols share udp/3074, all decoded from the game module itself:

  bdIPDiscovery       request 0x1E -> reply [u8 0x1E][u16 ver LE][bdAddr]      (9 B)
  bdNATTypeDiscovery  request 0x14 -> reply [u8 0x15][u16 ver][bdAddr sec][bdAddr mapped]
                      The reply type really is 0x15 while the request is 0x14:
                      receiveReplies (RPL 0x02a23ef0) drops anything else with no
                      log at all, which is what kept the console looping test 1.
  bdNATTraversal      [u8 type][u16 ver][u8[10] id][u32 hmac][bdAddr src][bdAddr dest]

bdNATTraversalPacket::deserialize (RPL 0x02a254c4) fixes that last layout at 29
bytes and rejects version < 2. bdNATTravClient::receiveFrom (RPL 0x02a21aa0)
gives the type table:

    0x0a  server-only packet, a client logs and ignores it
    0x0b  INTRO       - we send this to the peer being joined
    0x0c  INTRO_REPLY - that peer sends it straight back to the joiner, and it is
                        this outbound packet that punches its NAT open
    0x0e  KEEPALIVE   - client -> introducer every 15 s, both addresses empty

The joiner verifies the HMAC on the reply with a 28-byte key of its own
(doHMac, RPL 0x02a20048), so an introducer never has to compute one: it relays
the requester's HMAC untouched and only the requester checks it.

bdAddr on the wire is 4 raw IP bytes plus a little-endian u16 port. A default
constructed one reads back as 0.255.0.255:0.
"""
import socket
import struct
import select
import time

PRIMARY, ALT, SEC = 3074, 3075, 3076
# bdNetStartParams + 0x2 (RPL 0x02a0acdc) is the bdNet port used on BOTH ends:
# a console patched to 30000 sends from 30000 *to* 30000, so the responder has
# to answer there as well as on the stock 3074.
EXTRA_PORTS = [30000]
# The secAddr we advertise in the test-1 reply. It has to be a port we listen on
# (sendForTest3 aims there) AND differ from the port we answer test 2 from,
# because handleResponse (RPL 0x02a23b8c) calls it an Open NAT exactly when the
# test-2 reply arrives from the secAddr's IP on a *different* port.
#
# A real Demonware deployment has two public IPs and can run that test honestly.
# With one IP the honest version - answering from a port the console has never
# contacted - is dropped by any restrictive NAT, so every player fails test 2,
# falls through to "Test 3 failed. Strict NAT" and is reported Strict regardless
# of their actual connection. Three different routers all reading Strict is the
# tell. Since BO2 deprioritises strict-to-strict peers, that verdict is not just
# wrong, it is harmful - so answer test 2 from the primary port, which their NAT
# already accepts, and advertise a different one here.
ADV_SEC = SEC
import os
# The address this server is reachable at. It goes into the NAT-type reply as
# secAddr, so it has to be the real public address of this host.
SELF_IP = os.environ.get("BDNET_PUBLIC_IP", "127.0.0.1")

IP_T = 0x1E
NAT_REQ_T, NAT_REPLY_T = 0x14, 0x15
TRAV_SERVER, TRAV_INTRO, TRAV_INTRO_REPLY, TRAV_KEEPALIVE = 0x0A, 0x0B, 0x0C, 0x0E
TRAV_LEN = 29
EMPTY_ADDR = bytes([0x00, 0xFF, 0x00, 0xFF, 0x00, 0x00])


def bdaddr(ip, port):
    return socket.inet_aton(ip) + struct.pack("<H", port)


def parse_bdaddr(raw):
    if len(raw) < 6 or raw == EMPTY_ADDR:
        return None
    return (socket.inet_ntoa(raw[:4]), struct.unpack("<H", raw[4:6])[0])


def ip_reply(ip, port):
    return bytes([IP_T]) + struct.pack("<H", 2) + bdaddr(ip, port)


def nat_reply(cli_ip, cli_port):
    return (bytes([NAT_REPLY_T]) + struct.pack("<H", 2)
            + bdaddr(SELF_IP, ADV_SEC)
            + bdaddr(cli_ip, cli_port))


def mksock(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    return s


log = open("/tmp/bdnet4.log", "w")


def say(m):
    log.write(time.strftime("[%H:%M:%S] ") + m + "\n")
    log.flush()


socks = {}
for p in [PRIMARY, ALT, SEC] + EXTRA_PORTS:
    try:
        socks[p] = mksock(p)
        say("bound udp/%d" % p)
    except OSError as e:
        say("CANNOT BIND udp/%d: %s" % (p, e))

s_pri = socks.get(PRIMARY)
s_alt = socks.get(ALT)
say("responder v4 up: IP discovery + NAT type discovery + NAT traversal introducer")

# addr -> the local port that peer talks to us on. A console patched to bdNet
# port 30000 never contacts udp/3074, so relaying an INTRO to it from 3074 is
# a packet from an endpoint its NAT has never seen. Remember each peer's port
# and answer from the same one.
peer_port = {}
seen_types = {}
n_ip = 0

while True:
    r, _, _ = select.select(list(socks.values()), [], [], 1.0)
    for s in r:
        port = s.getsockname()[1]
        try:
            data, addr = s.recvfrom(2048)
        except OSError:
            continue
        if not data:
            continue
        t = data[0]

        if t == IP_T:
            s.sendto(ip_reply(addr[0], addr[1]), addr)
            n_ip += 1
            if n_ip <= 2:
                say(":%d IP <- %s from %s:%d" % (port, data.hex(), addr[0], addr[1]))
            continue

        if t == NAT_REQ_T:
            req = data[3] if len(data) > 3 else None
            reply = nat_reply(addr[0], addr[1])
            key = ("nat", port, req)
            seen_types[key] = seen_types.get(key, 0) + 1
            # Always answer on the socket the request arrived on. A console
            # patched to bdNet port 30000 has never talked to udp/3074, so a reply
            # from there is dropped by its NAT and test 2 fails - which is what
            # kept it reading Strict while consoles on 3074 were fine.
            #
            # handleResponse calls it an Open NAT when the reply's source port
            # differs from the advertised secAddr port, so ADV_SEC just has to be
            # a port no console talks to (3076) while this stays 3074 or 30000.
            s.sendto(reply, addr)
            if seen_types[key] <= 8:
                say(":%d NAT req=%s from %s:%d -> reply from :%d  secAddr=%s:%d"
                    % (port, req, addr[0], addr[1], port, SELF_IP, ADV_SEC))
            continue

        # Anything else that is 29 bytes and announces version >= 2 is a
        # traversal packet.
        if len(data) == TRAV_LEN:
            ver = struct.unpack("<H", data[1:3])[0]
            ident = data[3:13]
            hmac = data[13:17]
            src = parse_bdaddr(data[17:23])
            dest = parse_bdaddr(data[23:29])
            key = ("trav", t)
            seen_types[key] = seen_types.get(key, 0) + 1

            peer_port[addr] = port

            if t == TRAV_KEEPALIVE:
                if seen_types[key] % 20 == 1:
                    say(":%d KEEPALIVE #%d from %s:%d (ver=%d)"
                        % (port, seen_types[key], addr[0], addr[1], ver))
                continue

            say(":%d TRAV type=0x%02x ver=%d id=%s hmac=%s src=%s dest=%s from %s:%d"
                % (port, t, ver, ident.hex(), hmac.hex(), src, dest, addr[0], addr[1]))

            # An introduction request names the peer it wants reached. Flip the
            # type to INTRO and forward everything else BYTE FOR BYTE.
            #
            # Nothing else may change. doHMac (RPL 0x02a20048) computes the HMAC
            # over (identifier, addrSrc, addrDest), and the requester verifies it
            # again when the INTRO_REPLY comes back. Rewriting addrSrc - even to
            # the mapping we can see and the requester cannot - makes that check
            # compare an HMAC over our address against one taken over theirs, so
            # every reply is silently rejected and traversal never completes.
            if dest is not None:
                intro = bytes([TRAV_INTRO]) + data[1:]
                out = socks.get(peer_port.get(dest, PRIMARY), s_pri)
                try:
                    out.sendto(intro, dest)
                    say("  -> INTRO to %s:%d from udp/%d on behalf of %s:%d"
                        % (dest[0], dest[1], out.getsockname()[1], addr[0], addr[1]))
                except OSError as e:
                    say("  -> INTRO to %s failed: %s" % (dest, e))
            continue

        say(":%d ??? len=%d <- %s from %s:%d"
            % (port, len(data), data.hex()[:120], addr[0], addr[1]))
