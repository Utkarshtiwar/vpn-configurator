package com.example.vpntest;

import java.nio.charset.StandardCharsets;
import java.util.Locale;

/**
 * Small, dedicated helper for extracting a request hostname from a raw TCP
 * payload, without decrypting anything and without a full HTTP/TLS stack.
 *
 * Two cases are handled:
 *
 *   Plaintext HTTP:
 *     TCP payload -> HTTP request -> "Host:" header -> hostname
 *
 *   HTTPS:
 *     TCP payload -> TLS ClientHello (unencrypted handshake) -> SNI extension -> hostname
 *
 * TLS application data is never decrypted and no MITM is performed - only
 * the plaintext ClientHello handshake (which carries SNI in the clear) is
 * inspected. If neither a Host header nor a ClientHello/SNI can be found,
 * extractHostname(...) returns null; callers must not invent a hostname in
 * that case.
 */
final class RequestHostnameUtils {

    private RequestHostnameUtils() {}

    /**
     * @return the hostname extracted from this payload (HTTP Host header or
     *         TLS ClientHello SNI), or null if it could not be determined.
     */
    static String extractHostname(byte[] data, int length) {
        if (data == null || length <= 0) {
            return null;
        }

        String httpHost = extractHttpHost(data, length);
        if (httpHost != null) {
            return httpHost;
        }

        return extractTlsSni(data, length);
    }

    /**
     * Normalizes a hostname for comparison: trims whitespace, lowercases,
     * and strips an optional trailing ":port" (e.g. "Example.com:8080" ->
     * "example.com"). Returns null for null/blank input.
     */
    static String normalizeHostname(String hostname) {
        if (hostname == null) {
            return null;
        }

        String trimmed = hostname.trim();
        if (trimmed.isEmpty()) {
            return null;
        }

        // IPv6 literals in brackets (e.g. "[::1]:443") are left untouched;
        // not a scenario this hostname-matching feature targets.
        if (!trimmed.startsWith("[")) {
            int colonIdx = trimmed.indexOf(':');
            if (colonIdx > 0) {
                trimmed = trimmed.substring(0, colonIdx);
            }
        }

        return trimmed.toLowerCase(Locale.ROOT);
    }

    // ------------------------------------------------------------ HTTP

    private static String extractHttpHost(byte[] data, int length) {
        String text;
        try {
            text = new String(data, 0, length, StandardCharsets.ISO_8859_1);
        } catch (Exception e) {
            return null;
        }

        int firstLineEnd = text.indexOf("\r\n");
        if (firstLineEnd < 0) {
            firstLineEnd = text.indexOf('\n');
        }
        if (firstLineEnd < 0) {
            return null;
        }

        String requestLine = text.substring(0, firstLineEnd);
        if (!looksLikeHttpRequestLine(requestLine)) {
            return null;
        }

        int hostHeaderIdx = indexOfIgnoreCase(text, "Host:", firstLineEnd);
        if (hostHeaderIdx < 0) {
            return null;
        }

        int valueStart = hostHeaderIdx + "Host:".length();
        int lineEnd = text.indexOf('\n', valueStart);
        if (lineEnd < 0) {
            lineEnd = text.length();
        }

        String value = text.substring(valueStart, lineEnd);
        value = value.replace("\r", "").trim();

        return value.isEmpty() ? null : value;
    }

    private static boolean looksLikeHttpRequestLine(String line) {
        String[] methods = {
                "GET ", "POST ", "PUT ", "HEAD ", "DELETE ",
                "OPTIONS ", "CONNECT ", "PATCH ", "TRACE "
        };

        for (String method : methods) {
            if (line.startsWith(method)) {
                return true;
            }
        }
        return false;
    }

    private static int indexOfIgnoreCase(String haystack, String needle, int fromIndex) {
        if (fromIndex < 0 || fromIndex > haystack.length()) {
            return -1;
        }
        String lowerHaystack = haystack.toLowerCase(Locale.ROOT);
        String lowerNeedle = needle.toLowerCase(Locale.ROOT);
        return lowerHaystack.indexOf(lowerNeedle, fromIndex);
    }

    // ------------------------------------------------------------ TLS / SNI

    /**
     * Parses a (plaintext) TLS handshake record looking for a ClientHello
     * and its server_name (SNI) extension. Does NOT decrypt anything - the
     * ClientHello handshake message itself is sent unencrypted on the wire,
     * which is why SNI is visible here without MITM.
     */
    private static String extractTlsSni(byte[] data, int length) {
        try {
            int pos = 0;

            if (length < 6) {
                return null;
            }

            int contentType = data[pos] & 0xFF;
            if (contentType != 0x16) { // 0x16 = Handshake
                return null;
            }
            pos += 1;

            pos += 2; // record version, not needed

            if (pos + 2 > length) {
                return null;
            }
            pos += 2; // record length, not strictly needed below

            if (pos + 4 > length) {
                return null;
            }

            int handshakeType = data[pos] & 0xFF;
            if (handshakeType != 0x01) { // 0x01 = ClientHello
                return null;
            }
            pos += 1;

            pos += 3; // handshake body length (3 bytes), not needed

            if (pos + 2 > length) {
                return null;
            }
            pos += 2; // client_version

            if (pos + 32 > length) {
                return null;
            }
            pos += 32; // random

            if (pos + 1 > length) {
                return null;
            }
            int sessionIdLen = data[pos] & 0xFF;
            pos += 1;
            if (pos + sessionIdLen > length) {
                return null;
            }
            pos += sessionIdLen;

            if (pos + 2 > length) {
                return null;
            }
            int cipherSuitesLen = ((data[pos] & 0xFF) << 8) | (data[pos + 1] & 0xFF);
            pos += 2;
            if (pos + cipherSuitesLen > length) {
                return null;
            }
            pos += cipherSuitesLen;

            if (pos + 1 > length) {
                return null;
            }
            int compressionMethodsLen = data[pos] & 0xFF;
            pos += 1;
            if (pos + compressionMethodsLen > length) {
                return null;
            }
            pos += compressionMethodsLen;

            if (pos + 2 > length) {
                return null; // no extensions present in this segment
            }
            int extensionsLen = ((data[pos] & 0xFF) << 8) | (data[pos + 1] & 0xFF);
            pos += 2;

            int extensionsEnd = Math.min(length, pos + extensionsLen);

            while (pos + 4 <= extensionsEnd) {

                int extType = ((data[pos] & 0xFF) << 8) | (data[pos + 1] & 0xFF);
                int extLen = ((data[pos + 2] & 0xFF) << 8) | (data[pos + 3] & 0xFF);
                pos += 4;

                if (pos + extLen > extensionsEnd) {
                    break;
                }

                if (extType == 0x0000) { // server_name extension
                    String sni = parseServerNameExtension(data, pos, extLen);
                    if (sni != null) {
                        return sni;
                    }
                }

                pos += extLen;
            }

            return null;

        } catch (Exception e) {
            return null;
        }
    }

    private static String parseServerNameExtension(byte[] data, int offset, int extLen) {
        try {
            int pos = offset;
            int end = offset + extLen;

            if (pos + 2 > end) {
                return null;
            }
            int serverNameListLen = ((data[pos] & 0xFF) << 8) | (data[pos + 1] & 0xFF);
            pos += 2;

            int listEnd = Math.min(end, pos + serverNameListLen);

            while (pos + 3 <= listEnd) {
                int nameType = data[pos] & 0xFF;
                int nameLen = ((data[pos + 1] & 0xFF) << 8) | (data[pos + 2] & 0xFF);
                pos += 3;

                if (pos + nameLen > listEnd) {
                    break;
                }

                if (nameType == 0x00) { // host_name
                    return new String(data, pos, nameLen, StandardCharsets.US_ASCII);
                }

                pos += nameLen;
            }

            return null;

        } catch (Exception e) {
            return null;
        }
    }
}