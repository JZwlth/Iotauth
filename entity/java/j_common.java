package j_common;

import java.net.*;
import java.io.*;
import java.util.Arrays;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.security.SecureRandom;
import java.security.NoSuchAlgorithmException;

public class j_common {
    // msgType
    public static final byte AUTH_HELLO = 0;
    public static final byte ENTITY_HELLO = 1;
    public static final byte AUTH_SESSION_KEY_REQ = 10;
    public static final byte AUTH_SESSION_KEY_RESP = 11;
    public static final byte SESSION_KEY_REQ_IN_PUB_ENC = 20;
    public static final byte SESSION_KEY_RESP_WITH_DIST_KEY = 21;
    public static final byte SESSION_KEY_REQ = 22;
    public static final byte SESSION_KEY_RESP = 23;
    public static final byte SKEY_HANDSHAKE_1 = 30;
    public static final byte SKEY_HANDSHAKE_2 = 31;
    public static final byte SKEY_HANDSHAKE_3 = 32;
    public static final byte SECURE_COMM_MSG = 33;
    public static final byte FIN_SECURE_COMM = 34;
    public static final byte SECURE_PUB = 40;
    public static final byte MIGRATION_REQ_WITH_SIGN = 50;
    public static final byte MIGRATION_RESP_WITH_SIGN = 51;
    public static final byte MIGRATION_REQ_WITH_MAC = 52;
    public static final byte MIGRATION_RESP_WITH_MAC = 53;
    public static final byte ADD_READER_REQ_IN_PUB_ENC = 60;
    public static final byte ADD_READER_RESP_WITH_DIST_KEY = 61;
    public static final byte ADD_READER_REQ = 62;
    public static final byte ADD_READER_RESP = 63;
    public static final byte AUTH_ALERT = 100;

    // Size constants
    public static final int MAX_PAYLOAD_LENGTH = 1024;
    public static final int MAX_HS_BUF_LENGTH = 256;
    public static final int MAX_ERROR_MESSAGE_LENGTH = 128;
    public static final int AUTH_ID_LEN = 4;
    public static final int NUMKEY_SIZE = 4;
    public static final int NONCE_SIZE = 8;
    public static final int MAC_SIZE = 32;
    public static final int KEY_ID_SIZE = 8;
    public static final int HS_NONCE_SIZE = 8;

    // Struct-like Classes
    public static class HSNonce {
        public byte[] nonce = new byte[HS_NONCE_SIZE];
        public byte[] reply_nonce = new byte[HS_NONCE_SIZE];
        public byte[] dhParam; // Variable size, initialize as needed

        public HSNonce(byte[] dhParam) {
            this.dhParam = dhParam;
        }
    }

    // Utility Methods
    public static void error_exit(String message) {
        System.err.println(message);
        System.exit(1);
    }

    public static void print_buf(byte[] buf) {
        StringBuilder hex = new StringBuilder();
        for (byte b : buf) {
            hex.append(String.format(" %.2x", b));
        }
        System.out.println("Hex:" + hex.toString());
    }

    public static long read_unsigned_long_int_BE(byte[] buf) {
        long result = 0;
        for (int i = 0; i < buf.length; i++) {
            result = (result << 8) + (buf[i] & 0xff);
        }
        return result;
    }

    public static void writeToNBytes(long num, int n, byte[] buf) {
        for (int i = 0; i < n; i++) {
            buf[i] = (byte) (num >> 8 * (n - 1 - i));
        }
    }

    public static long readUnsignedLongBE(byte[] buf) {
        long num = 0;
        for (int i = 0; i < buf.length; i++) {
            num |= ((long) buf[i] & 0xff) << (8 * (buf.length - 1 - i));
        }
        return num;
    }

    public static byte[] parseReceivedMessage(byte[] receivedBuf, int[] messageType, int[] dataBufLength) {
        messageType[0] = receivedBuf[0];
        int varLengthBufSize = readVariableLength(receivedBuf, 1, dataBufLength);
        return java.util.Arrays.copyOfRange(receivedBuf, 1 + varLengthBufSize, receivedBuf.length);
    }

    public static int readVariableLength(byte[] buf, int offset, int[] num) {
        int result = 0;
        int shift = 0;
        num[0] = 0;
        while (true) {
            byte b = buf[offset++];
            result |= (b & 0x7F) << shift;
            if ((b & 0x80) == 0) break;
            shift += 7;
        }
        num[0] = result;
        return offset;
    }

    public static Socket connectAsClient(String ipAddr, int portNum) {
        try {
            Socket socket = new Socket(ipAddr, portNum);
            System.out.println("------------Connected-------------");
            return socket;
        } catch (IOException e) {
            errorExit("Connection error: " + e.getMessage());
            return null; // Unreachable code; only for compiler satisfaction.
        }
    }

    public static int mod(int a, int b) {
        int r = a % b;
        return r < 0 ? r + b : r;
    }

    public static void serializeHandshake(byte[] nonce, byte[] replyNonce, byte[] ret) {
        if (nonce == null && replyNonce == null) {
            errorExit("Error: handshake should include at least one nonce.");
        }
        int index = 1;
        ret[0] = 0;
        if (nonce != null) {
            ret[0] |= 1;
            System.arraycopy(nonce, 0, ret, index, HS_NONCE_SIZE);
            index += HS_NONCE_SIZE;
        }
        if (replyNonce != null) {
            ret[0] |= 2;
            System.arraycopy(replyNonce, 0, ret, index, HS_NONCE_SIZE);
        }
    }


}

