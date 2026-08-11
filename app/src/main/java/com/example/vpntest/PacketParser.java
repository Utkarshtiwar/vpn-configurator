package com.example.vpntest;

import java.net.InetAddress;
import java.net.UnknownHostException;


final class PacketParser {

    // Protocol / Next Header numbers this parser understands as "transport".
    static final int PROTO_ICMPV4 = 1;
    static final int PROTO_TCP = 6;
    static final int PROTO_UDP = 17;
    static final int PROTO_ICMPV6 = 58;

    // IPv6 extension header type numbers.
    private static final int EXT_HOP_BY_HOP = 0;
    private static final int EXT_ROUTING = 43;
    private static final int EXT_FRAGMENT = 44;
    private static final int EXT_DESTINATION_OPTIONS = 60;

    private PacketParser() {}

    static ParsedPacket parse(byte[] packet, int length) {
        if (packet == null || length < 1) {
            return ParsedPacket.malformed("Empty packet");
        }

        int version = (packet[0] >> 4) & 0xF;

        if (version == 4) {
            return parseIPv4(packet, length);
        } else if (version == 6) {
            return parseIPv6(packet, length);
        }

        return ParsedPacket.malformed("Unsupported IP version: " + version);
    }

    // ---------------------------------------------------------------- IPv4

    private static ParsedPacket parseIPv4(byte[] packet, int length) {
        if (length < 20) {
            return ParsedPacket.malformed("IPv4 packet shorter than minimum header (20 bytes)");
        }

        int ihl = packet[0] & 0x0F;
        int ipHeaderLength = ihl * 4;

        if (ipHeaderLength < 20 || length < ipHeaderLength) {
            return ParsedPacket.malformed("Invalid IPv4 IHL / header length exceeds packet length");
        }

        int protocol = packet[9] & 0xFF;
        int ttl = packet[8] & 0xFF;

        int flagsAndFragmentOffset = ((packet[6] & 0xFF) << 8) | (packet[7] & 0xFF);
        int fragmentOffset = flagsAndFragmentOffset & 0x1FFF;
        boolean isFirstFragment = fragmentOffset == 0;

        byte[] srcBytes = new byte[4];
        byte[] dstBytes = new byte[4];
        System.arraycopy(packet, 12, srcBytes, 0, 4);
        System.arraycopy(packet, 16, dstBytes, 0, 4);

        String srcStr = ipv4ToString(srcBytes);
        String dstStr = ipv4ToString(dstBytes);

        int payloadLength = length - ipHeaderLength;

        if (!isFirstFragment) {
            return ParsedPacket.nonFirstFragment(4, srcStr, dstStr, srcBytes, dstBytes,
                    protocol, ipHeaderLength, ttl, payloadLength);
        }

        int transportHeaderOffset = ipHeaderLength;
        int sourcePort = -1;
        int destinationPort = -1;

        if (protocol == PROTO_TCP || protocol == PROTO_UDP) {
            if (length < transportHeaderOffset + 4) {
                return ParsedPacket.malformed("IPv4 packet too short to read transport ports");
            }
            sourcePort = readUint16(packet, transportHeaderOffset);
            destinationPort = readUint16(packet, transportHeaderOffset + 2);
        }

        return ParsedPacket.ok(4, srcStr, dstStr, srcBytes, dstBytes, protocol,
                transportHeaderOffset, ipHeaderLength, sourcePort, destinationPort,
                ttl, payloadLength);
    }

    // ---------------------------------------------------------------- IPv6

    private static ParsedPacket parseIPv6(byte[] packet, int length) {
        if (length < 40) {
            return ParsedPacket.malformed("IPv6 packet shorter than fixed header (40 bytes)");
        }

        int payloadLength = ((packet[4] & 0xFF) << 8) | (packet[5] & 0xFF);
        int nextHeader = packet[6] & 0xFF;
        int hopLimit = packet[7] & 0xFF;

        byte[] srcBytes = new byte[16];
        byte[] dstBytes = new byte[16];
        System.arraycopy(packet, 8, srcBytes, 0, 16);
        System.arraycopy(packet, 24, dstBytes, 0, 16);

        String srcStr;
        String dstStr;
        try {
            srcStr = InetAddress.getByAddress(srcBytes).getHostAddress();
            dstStr = InetAddress.getByAddress(dstBytes).getHostAddress();
        } catch (UnknownHostException e) {
            return ParsedPacket.malformed("Failed to convert IPv6 address bytes: " + e.getMessage());
        }

        int offset = 40;
        int header = nextHeader;

        while (true) {
            switch (header) {
                case EXT_HOP_BY_HOP:
                case EXT_ROUTING:
                case EXT_DESTINATION_OPTIONS: {
                    if (offset + 2 > length) {
                        return ParsedPacket.malformed("Truncated IPv6 extension header (type " + header + ")");
                    }
                    int nextHdr = packet[offset] & 0xFF;
                    int hdrExtLen = packet[offset + 1] & 0xFF;
                    int extLen = (hdrExtLen + 1) * 8;
                    if (extLen <= 0 || offset + extLen > length) {
                        return ParsedPacket.malformed("IPv6 extension header exceeds packet length (type " + header + ")");
                    }
                    header = nextHdr;
                    offset += extLen;
                    continue;
                }
                case EXT_FRAGMENT: {
                    // Fixed 8-byte fragment header.
                    if (offset + 8 > length) {
                        return ParsedPacket.malformed("Truncated IPv6 fragment header");
                    }
                    int nextHdr = packet[offset] & 0xFF;
                    int fragOffsetAndFlags = ((packet[offset + 2] & 0xFF) << 8) | (packet[offset + 3] & 0xFF);
                    int fragOffset = (fragOffsetAndFlags >> 3) & 0x1FFF;
                    boolean isFirstFragment = fragOffset == 0;
                    int nextOffset = offset + 8;

                    if (!isFirstFragment) {
                        // Transport header is not present in this packet at all.
                        return ParsedPacket.nonFirstFragment(6, srcStr, dstStr, srcBytes, dstBytes,
                                nextHdr, nextOffset, hopLimit, payloadLength);
                    }

                    header = nextHdr;
                    offset = nextOffset;
                    continue;
                }
                default:
                    // Reached the real transport protocol (or an unsupported one) - stop walking.
                    break;
            }
            break;
        }

        int transportProtocol = header;
        int transportHeaderOffset = offset;

        int sourcePort = -1;
        int destinationPort = -1;

        if (transportProtocol == PROTO_TCP || transportProtocol == PROTO_UDP) {
            if (length < transportHeaderOffset + 4) {
                return ParsedPacket.malformed("IPv6 packet too short to read transport ports");
            }
            sourcePort = readUint16(packet, transportHeaderOffset);
            destinationPort = readUint16(packet, transportHeaderOffset + 2);
        }

        return ParsedPacket.ok(6, srcStr, dstStr, srcBytes, dstBytes, transportProtocol,
                transportHeaderOffset, 40, sourcePort, destinationPort,
                hopLimit, payloadLength);
    }

    // -------------------------------------------------------------- helpers

    private static int readUint16(byte[] b, int off) {
        return ((b[off] & 0xFF) << 8) | (b[off + 1] & 0xFF);
    }

    private static String ipv4ToString(byte[] ip) {
        return (ip[0] & 0xFF) + "." + (ip[1] & 0xFF) + "." + (ip[2] & 0xFF) + "." + (ip[3] & 0xFF);
    }

    static String protocolName(int protocol) {
        switch (protocol) {
            case PROTO_TCP: return "TCP";
            case PROTO_UDP: return "UDP";
            case PROTO_ICMPV4: return "ICMP";
            case PROTO_ICMPV6: return "ICMPv6";
            default: return "OTHER(" + protocol + ")";
        }
    }
}