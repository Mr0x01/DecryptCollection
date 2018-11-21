package shiyu;

import java.io.*;
import java.security.*;

public class DES
{
    static final String NAME = "DES";
    static final boolean IN = true;
    static final boolean OUT = false;
    static final int debuglevel = 0;
    static final PrintWriter err;
    private static final int ROUNDS = 16;
    private static final int BLOCK_SIZE = 8;
    private static final int[] SKB;
    private static final int[] SP_TRANS;
    private static final char[] HEX_DIGITS;
    
    static {
        err = null;
        SKB = new int[512];
        SP_TRANS = new int[512];
        HEX_DIGITS = new char[] { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
        final String cd = "D]PKESYM`UBJ\\@RXA`I[T`HC`LZQ\\PB]TL`[C`JQ@Y`HSXDUIZRAM`EK";
        int count = 0;
        int offset = 0;
        for (int i = 0; i < cd.length(); ++i) {
            final int s = cd.charAt(i) - '@';
            if (s != 32) {
                final int bit = 1 << count++;
                for (int j = 0; j < 64; ++j) {
                    if ((bit & j) != 0x0) {
                        final int[] skb = DES.SKB;
                        final int n = offset + j;
                        skb[n] |= 1 << s;
                    }
                }
                if (count == 6) {
                    offset += 64;
                    count = 0;
                }
            }
        }
        final String spt = "g3H821:80:H03BA0@N1290BAA88::3112aIH8:8282@0@AH0:1W3A8P810@22;22A18^@9H9@129:<8@822`?:@0@8PH2H81A19:G1@03403A0B1;:0@1g192:@919AA0A109:W21492H@0051919811:215011139883942N8::3112A2:31981jM118::A101@I88:1aN0<@030128:X;811`920:;H0310D1033@W980:8A4@804A3803o1A2021B2:@1AH023GA:8:@81@@12092B:098042P@:0:A0HA9>1;289:@1804:40Ph=1:H0I0HP0408024bC9P8@I808A;@0@0PnH0::8:19J@818:@iF0398:8A9H0<13@001@11<8;@82B01P0a2989B:0AY0912889bD0A1@B1A0A0AB033O91182440A9P8@I80n@1I03@1J828212A`A8:12B1@19A9@9@8^B:0@H00<82AB030bB840821Q:8310A302102::A1::20A1;8";
        offset = 0;
        for (int k = 0; k < 32; ++k) {
            int l = -1;
            final int bit = 1 << k;
            for (int j = 0; j < 32; ++j) {
                final int c = spt.charAt(offset >> 1) - '0' >> (offset & 0x1) * 3 & '\u0007';
                ++offset;
                if (c < 5) {
                    l += c + 1;
                    final int[] sp_TRANS = DES.SP_TRANS;
                    final int n2 = l;
                    sp_TRANS[n2] |= bit;
                }
                else {
                    final int param = spt.charAt(offset >> 1) - '0' >> (offset & 0x1) * 3 & '\u0007';
                    ++offset;
                    if (c == 5) {
                        l += param + 6;
                        final int[] sp_TRANS2 = DES.SP_TRANS;
                        final int n3 = l;
                        sp_TRANS2[n3] |= bit;
                    }
                    else if (c == 6) {
                        l += (param << 6) + 1;
                        final int[] sp_TRANS3 = DES.SP_TRANS;
                        final int n4 = l;
                        sp_TRANS3[n4] |= bit;
                    }
                    else {
                        l += param << 6;
                        --j;
                    }
                }
            }
        }
    }
    
    protected static final boolean areEqual(final byte[] a, final byte[] b) {
        final int aLength = a.length;
        if (aLength != b.length) {
            return false;
        }
        for (int i = 0; i < aLength; ++i) {
            if (a[i] != b[i]) {
                return false;
            }
        }
        return true;
    }
    
    protected static byte[] blockDecrypt(final byte[] in, int inOffset, final Object sessionKey) {
        final int[] L_R = { (in[inOffset++] & 0xFF) | (in[inOffset++] & 0xFF) << 8 | (in[inOffset++] & 0xFF) << 16 | (in[inOffset++] & 0xFF) << 24, (in[inOffset++] & 0xFF) | (in[inOffset++] & 0xFF) << 8 | (in[inOffset++] & 0xFF) << 16 | (in[inOffset] & 0xFF) << 24 };
        IP(L_R);
        decrypt(L_R, sessionKey);
        FP(L_R);
        final int L = L_R[0];
        final int R = L_R[1];
        final byte[] result = { (byte)L, (byte)(L >> 8), (byte)(L >> 16), (byte)(L >> 24), (byte)R, (byte)(R >> 8), (byte)(R >> 16), (byte)(R >> 24) };
        return result;
    }
    
    protected static byte[] blockEncrypt(final byte[] in, int inOffset, final Object sessionKey) {
        final int[] L_R = { (in[inOffset++] & 0xFF) | (in[inOffset++] & 0xFF) << 8 | (in[inOffset++] & 0xFF) << 16 | (in[inOffset++] & 0xFF) << 24, (in[inOffset++] & 0xFF) | (in[inOffset++] & 0xFF) << 8 | (in[inOffset++] & 0xFF) << 16 | (in[inOffset] & 0xFF) << 24 };
        IP(L_R);
        encrypt(L_R, sessionKey);
        FP(L_R);
        final int L = L_R[0];
        final int R = L_R[1];
        final byte[] result = { (byte)L, (byte)(L >> 8), (byte)(L >> 16), (byte)(L >> 24), (byte)R, (byte)(R >> 8), (byte)(R >> 16), (byte)(R >> 24) };
        return result;
    }
    
    protected static int[] crypt3(final int L0, final int R0, final Object sessionKey) {
        final int[] sKey = (int[])sessionKey;
        int L = 0;
        int R = 0;
        final int n = sKey.length;
        for (int i = 0; i < 25; ++i) {
            int v;
            int u;
            int t;
            for (int j = 0; j < n; u ^= (u << 16 ^ R ^ sKey[j++]), t = (v ^ v << 16 ^ R ^ sKey[j++]), t = (t >>> 4 | t << 28), L ^= (DES.SP_TRANS[0x40 | (t & 0x3F)] | DES.SP_TRANS[0xC0 | (t >>> 8 & 0x3F)] | DES.SP_TRANS[0x140 | (t >>> 16 & 0x3F)] | DES.SP_TRANS[0x1C0 | (t >>> 24 & 0x3F)] | DES.SP_TRANS[u & 0x3F] | DES.SP_TRANS[0x80 | (u >>> 8 & 0x3F)] | DES.SP_TRANS[0x100 | (u >>> 16 & 0x3F)] | DES.SP_TRANS[0x180 | (u >>> 24 & 0x3F)]), v = (L ^ L >>> 16), u = (v & L0), v &= R0, u ^= (u << 16 ^ L ^ sKey[j++]), t = (v ^ v << 16 ^ L ^ sKey[j++]), t = (t >>> 4 | t << 28), R ^= (DES.SP_TRANS[0x40 | (t & 0x3F)] | DES.SP_TRANS[0xC0 | (t >>> 8 & 0x3F)] | DES.SP_TRANS[0x140 | (t >>> 16 & 0x3F)] | DES.SP_TRANS[0x1C0 | (t >>> 24 & 0x3F)] | DES.SP_TRANS[u & 0x3F] | DES.SP_TRANS[0x80 | (u >>> 8 & 0x3F)] | DES.SP_TRANS[0x100 | (u >>> 16 & 0x3F)] | DES.SP_TRANS[0x180 | (u >>> 24 & 0x3F)])) {
                v = (R ^ R >>> 16);
                u = (v & L0);
                v &= R0;
            }
            t = L;
            L = R;
            R = t;
        }
        final int[] result = { R >>> 1 | R << 31, L >>> 1 | L << 31 };
        FP(result);
        return result;
    }
    
    static void debug(final String s) {
        DES.err.println(">>> DES: " + s);
    }
    
    protected static final void decrypt(final byte[] io, final Object sessionKey) {
        final int[] L_R = { (io[0] & 0xFF) | (io[1] & 0xFF) << 8 | (io[2] & 0xFF) << 16 | (io[3] & 0xFF) << 24, (io[4] & 0xFF) | (io[5] & 0xFF) << 8 | (io[6] & 0xFF) << 16 | (io[7] & 0xFF) << 24 };
        decrypt(L_R, sessionKey);
        final int L = L_R[0];
        final int R = L_R[1];
        io[0] = (byte)L;
        io[1] = (byte)(L >> 8);
        io[2] = (byte)(L >> 16);
        io[3] = (byte)(L >> 24);
        io[4] = (byte)R;
        io[5] = (byte)(R >> 8);
        io[6] = (byte)(R >> 16);
        io[7] = (byte)(R >> 24);
    }
    
    protected static final void decrypt(final int[] io, final Object sessionKey) {
        final int[] sKey = (int[])sessionKey;
        int L = io[0];
        int R = io[1];
        int u = R << 1 | R >>> 31;
        R = (L << 1 | L >>> 31);
        L = u;
        final int n = sKey.length;
        int t;
        for (int i = n - 1; i > 0; t = (R ^ sKey[i--]), u = (R ^ sKey[i--]), t = (t >>> 4 | t << 28), L ^= (DES.SP_TRANS[0x40 | (t & 0x3F)] | DES.SP_TRANS[0xC0 | (t >>> 8 & 0x3F)] | DES.SP_TRANS[0x140 | (t >>> 16 & 0x3F)] | DES.SP_TRANS[0x1C0 | (t >>> 24 & 0x3F)] | DES.SP_TRANS[u & 0x3F] | DES.SP_TRANS[0x80 | (u >>> 8 & 0x3F)] | DES.SP_TRANS[0x100 | (u >>> 16 & 0x3F)] | DES.SP_TRANS[0x180 | (u >>> 24 & 0x3F)]), t = (L ^ sKey[i--]), u = (L ^ sKey[i--]), t = (t >>> 4 | t << 28), R ^= (DES.SP_TRANS[0x40 | (t & 0x3F)] | DES.SP_TRANS[0xC0 | (t >>> 8 & 0x3F)] | DES.SP_TRANS[0x140 | (t >>> 16 & 0x3F)] | DES.SP_TRANS[0x1C0 | (t >>> 24 & 0x3F)] | DES.SP_TRANS[u & 0x3F] | DES.SP_TRANS[0x80 | (u >>> 8 & 0x3F)] | DES.SP_TRANS[0x100 | (u >>> 16 & 0x3F)] | DES.SP_TRANS[0x180 | (u >>> 24 & 0x3F)])) {}
        io[0] = (L >>> 1 | L << 31);
        io[1] = (R >>> 1 | R << 31);
    }
    
    public void doit() {
        final boolean ok = false;
        final int BLOCK_SIZE = 8;
        try {
            final byte[] kb = new byte[BLOCK_SIZE];
            byte[] pt = new byte[BLOCK_SIZE];
            for (int i = 0; i < BLOCK_SIZE; ++i) {
                kb[i] = (byte)i;
            }
            for (int i = 0; i < BLOCK_SIZE; ++i) {
                pt[i] = (byte)i;
            }
            Object key = makeKey(kb);
            byte[] ct = blockEncrypt(pt, 0, key);
            byte[] tmp = blockDecrypt(ct, 0, key);
            System.out.println("       key: " + toString(kb));
            System.out.println(" plaintext: " + toString(pt));
            System.out.println("ciphertext: " + toString(ct));
            System.out.println("  computed: " + toString(tmp));
            final String[][] kat = { { "0101010101010101", "95f8a5e5dd31d900", "8000000000000000" }, { "0101010101010101", "dd7f121ca5015619", "4000000000000000" }, { "0101010101010101", "2e8653104f3834ea", "2000000000000000" }, { "0123456789abcdef", "0123456789abcde7", "c95744256a5ed31d" }, { "0123456710325476", "89abcdef98badcfe", "f0148eff050b2716" } };
            int i = 0;
            while (i < kat.length) {
                key = makeKey(fromString(kat[i][0]));
                pt = fromString(kat[i][1]);
                ct = fromString(kat[i][2]);
                ++i;
                tmp = blockEncrypt(pt, 0, key);
                System.out.println("KAT triple #" + i);
                System.out.println("       key: " + toString(kb));
                System.out.println(" plaintext: " + toString(pt));
                System.out.println("ciphertext: " + toString(ct));
                System.out.println("  computed: " + toString(tmp));
                tmp = blockDecrypt(ct, 0, key);
                System.out.println("KAT triple #" + i);
                System.out.println("       key: " + toString(kb));
                System.out.println("ciphertext: " + toString(ct));
                System.out.println(" plaintext: " + toString(pt));
                System.out.println("  computed: " + toString(tmp));
            }
            key = makeKey(fromString(kat[0][0]));
            final String strSrc = "a \u4e2d\u56fd\u5730\u5927\u7269\u535a\u4e2d\u56fd";
            String strCpt = "";
            String strDes = "";
            int intSrc = strSrc.getBytes().length;
            int intTemp;
            if (intSrc % 8 == 0) {
                intTemp = 0;
            }
            else {
                intTemp = 1;
            }
            int intBlock = intSrc / 8 + intTemp;
            byte[] bytBlock = new byte[intBlock * 8];
            bytBlock = strSrc.getBytes();
            final byte[] oBlock = new byte[8];
            for (int iBlock = 0; iBlock < intBlock; ++iBlock) {
                int intpt;
                if (iBlock < intBlock - 1 || intSrc % 8 == 0) {
                    intpt = 8;
                }
                else {
                    intpt = intSrc % 8;
                }
                if (intpt < 8) {
                    for (int ipt = 0; ipt < 8; ++ipt) {
                        oBlock[ipt] = fromString("00")[0];
                    }
                }
                for (int iob = 0; iob < intpt; ++iob) {
                    oBlock[iob] = bytBlock[iBlock * 8 + iob];
                }
                final byte[] bytCpt = blockEncrypt(oBlock, 0, key);
                strCpt = String.valueOf(strCpt) + toString(bytCpt);
            }
            System.out.println("\u539f: " + strSrc);
            System.out.println("\u5bc6: " + strCpt);
            intSrc = strCpt.length();
            intBlock = intSrc / 16;
            bytBlock = new byte[intSrc / 2];
            final String[] strBlockc = new String[intBlock];
            for (int iBlock2 = 0; iBlock2 < intBlock; ++iBlock2) {
                strBlockc[iBlock2] = strCpt.substring(iBlock2 * 16, iBlock2 * 16 + 16);
                ct = fromString(strBlockc[iBlock2]);
                tmp = blockDecrypt(ct, 0, key);
                for (int iob2 = 0; iob2 < 8; ++iob2) {
                    bytBlock[iBlock2 * 8 + iob2] = tmp[iob2];
                }
            }
            strDes = new String(bytBlock);
            System.out.println("\u89e3: " + strDes.trim());
        }
        catch (Exception x) {
            System.out.println("\u9519\u8bef: " + x.getMessage());
        }
    }
    
    protected static final void encrypt(final byte[] io, final Object sessionKey) {
        final int[] L_R = { (io[0] & 0xFF) | (io[1] & 0xFF) << 8 | (io[2] & 0xFF) << 16 | (io[3] & 0xFF) << 24, (io[4] & 0xFF) | (io[5] & 0xFF) << 8 | (io[6] & 0xFF) << 16 | (io[7] & 0xFF) << 24 };
        encrypt(L_R, sessionKey);
        final int L = L_R[0];
        final int R = L_R[1];
        io[0] = (byte)L;
        io[1] = (byte)(L >> 8);
        io[2] = (byte)(L >> 16);
        io[3] = (byte)(L >> 24);
        io[4] = (byte)R;
        io[5] = (byte)(R >> 8);
        io[6] = (byte)(R >> 16);
        io[7] = (byte)(R >> 24);
    }
    
    protected static final void encrypt(final int[] io, final Object sessionKey) {
        final int[] sKey = (int[])sessionKey;
        int L = io[0];
        int R = io[1];
        int u = R << 1 | R >>> 31;
        R = (L << 1 | L >>> 31);
        L = u;
        int t;
        for (int n = sKey.length, i = 0; i < n; u = (R ^ sKey[i++]), t = (R ^ sKey[i++]), t = (t >>> 4 | t << 28), L ^= (DES.SP_TRANS[0x40 | (t & 0x3F)] | DES.SP_TRANS[0xC0 | (t >>> 8 & 0x3F)] | DES.SP_TRANS[0x140 | (t >>> 16 & 0x3F)] | DES.SP_TRANS[0x1C0 | (t >>> 24 & 0x3F)] | DES.SP_TRANS[u & 0x3F] | DES.SP_TRANS[0x80 | (u >>> 8 & 0x3F)] | DES.SP_TRANS[0x100 | (u >>> 16 & 0x3F)] | DES.SP_TRANS[0x180 | (u >>> 24 & 0x3F)]), u = (L ^ sKey[i++]), t = (L ^ sKey[i++]), t = (t >>> 4 | t << 28), R ^= (DES.SP_TRANS[0x40 | (t & 0x3F)] | DES.SP_TRANS[0xC0 | (t >>> 8 & 0x3F)] | DES.SP_TRANS[0x140 | (t >>> 16 & 0x3F)] | DES.SP_TRANS[0x1C0 | (t >>> 24 & 0x3F)] | DES.SP_TRANS[u & 0x3F] | DES.SP_TRANS[0x80 | (u >>> 8 & 0x3F)] | DES.SP_TRANS[0x100 | (u >>> 16 & 0x3F)] | DES.SP_TRANS[0x180 | (u >>> 24 & 0x3F)])) {}
        io[0] = (L >>> 1 | L << 31);
        io[1] = (R >>> 1 | R << 31);
    }
    
    protected static int engineBlockSize() {
        return 8;
    }
    
    protected static final void FP(final byte[] io) {
        final int[] L_R = { (io[0] & 0xFF) | (io[1] & 0xFF) << 8 | (io[2] & 0xFF) << 16 | (io[3] & 0xFF) << 24, (io[4] & 0xFF) | (io[5] & 0xFF) << 8 | (io[6] & 0xFF) << 16 | (io[7] & 0xFF) << 24 };
        FP(L_R);
        final int L = L_R[0];
        final int R = L_R[1];
        io[0] = (byte)L;
        io[1] = (byte)(L >> 8);
        io[2] = (byte)(L >> 16);
        io[3] = (byte)(L >> 24);
        io[4] = (byte)R;
        io[5] = (byte)(R >> 8);
        io[6] = (byte)(R >> 16);
        io[7] = (byte)(R >> 24);
    }
    
    protected static final void FP(final int[] io) {
        int L = io[0];
        int R = io[1];
        int t = (R >>> 1 ^ L) & 0x55555555;
        L ^= t;
        R ^= t << 1;
        t = ((L >>> 8 ^ R) & 0xFF00FF);
        R ^= t;
        L ^= t << 8;
        t = ((R >>> 2 ^ L) & 0x33333333);
        L ^= t;
        R ^= t << 2;
        t = ((L >>> 16 ^ R) & 0xFFFF);
        R ^= t;
        L ^= t << 16;
        t = ((R >>> 4 ^ L) & 0xF0F0F0F);
        io[0] = (L ^ t);
        io[1] = (R ^ t << 4);
    }
    
    protected static final int fromDigit(final char ch) {
        if (ch >= '0' && ch <= '9') {
            return ch - '0';
        }
        if (ch >= 'A' && ch <= 'F') {
            return ch - 'A' + '\n';
        }
        if (ch >= 'a' && ch <= 'f') {
            return ch - 'a' + '\n';
        }
        throw new IllegalArgumentException("Invalid hex digit '" + ch + "'");
    }
    
    protected static final byte[] fromString(final String hex) {
        final int len = hex.length();
        final byte[] buf = new byte[(len + 1) / 2];
        int i = 0;
        int j = 0;
        if (len % 2 == 1) {
            buf[j++] = (byte)fromDigit(hex.charAt(i++));
        }
        while (i < len) {
            buf[j++] = (byte)(fromDigit(hex.charAt(i++)) << 4 | fromDigit(hex.charAt(i++)));
        }
        return buf;
    }
    
    protected static final void IP(final byte[] io) {
        final int[] L_R = { (io[0] & 0xFF) | (io[1] & 0xFF) << 8 | (io[2] & 0xFF) << 16 | (io[3] & 0xFF) << 24, (io[4] & 0xFF) | (io[5] & 0xFF) << 8 | (io[6] & 0xFF) << 16 | (io[7] & 0xFF) << 24 };
        IP(L_R);
        final int L = L_R[0];
        final int R = L_R[1];
        io[0] = (byte)L;
        io[1] = (byte)(L >> 8);
        io[2] = (byte)(L >> 16);
        io[3] = (byte)(L >> 24);
        io[4] = (byte)R;
        io[5] = (byte)(R >> 8);
        io[6] = (byte)(R >> 16);
        io[7] = (byte)(R >> 24);
    }
    
    protected static final void IP(final int[] io) {
        int L = io[0];
        int R = io[1];
        int t = (R >>> 4 ^ L) & 0xF0F0F0F;
        L ^= t;
        R ^= t << 4;
        t = ((L >>> 16 ^ R) & 0xFFFF);
        R ^= t;
        L ^= t << 16;
        t = ((R >>> 2 ^ L) & 0x33333333);
        L ^= t;
        R ^= t << 2;
        t = ((L >>> 8 ^ R) & 0xFF00FF);
        R ^= t;
        L ^= t << 8;
        t = ((R >>> 1 ^ L) & 0x55555555);
        io[0] = (L ^ t);
        io[1] = (R ^ t << 1);
    }
    
    protected static synchronized Object makeKey(final byte[] k) throws InvalidKeyException {
        int i = 0;
        int L = (k[i++] & 0xFF) | (k[i++] & 0xFF) << 8 | (k[i++] & 0xFF) << 16 | (k[i++] & 0xFF) << 24;
        int R = (k[i++] & 0xFF) | (k[i++] & 0xFF) << 8 | (k[i++] & 0xFF) << 16 | (k[i++] & 0xFF) << 24;
        int t = (R >>> 4 ^ L) & 0xF0F0F0F;
        L ^= t;
        R ^= t << 4;
        t = ((L << 18 ^ L) & 0xCCCC0000);
        L ^= (t ^ t >>> 18);
        t = ((R << 18 ^ R) & 0xCCCC0000);
        R ^= (t ^ t >>> 18);
        t = ((R >>> 1 ^ L) & 0x55555555);
        L ^= t;
        R ^= t << 1;
        t = ((L >>> 8 ^ R) & 0xFF00FF);
        R ^= t;
        L ^= t << 8;
        t = ((R >>> 1 ^ L) & 0x55555555);
        L ^= t;
        R ^= t << 1;
        R = ((R & 0xFF) << 16 | (R & 0xFF00) | (R & 0xFF0000) >>> 16 | (L & 0xF0000000) >>> 4);
        L &= 0xFFFFFFF;
        int j = 0;
        final int[] sKey = new int[32];
        for (i = 0; i < 16; ++i) {
            if ((32508 >> i & 0x1) == 0x1) {
                L = ((L >>> 2 | L << 26) & 0xFFFFFFF);
                R = ((R >>> 2 | R << 26) & 0xFFFFFFF);
            }
            else {
                L = ((L >>> 1 | L << 27) & 0xFFFFFFF);
                R = ((R >>> 1 | R << 27) & 0xFFFFFFF);
            }
            int s = DES.SKB[L & 0x3F] | DES.SKB[0x40 | ((L >>> 6 & 0x3) | (L >>> 7 & 0x3C))] | DES.SKB[0x80 | ((L >>> 13 & 0xF) | (L >>> 14 & 0x30))] | DES.SKB[0xC0 | ((L >>> 20 & 0x1) | (L >>> 21 & 0x6) | (L >>> 22 & 0x38))];
            t = (DES.SKB[0x100 | (R & 0x3F)] | DES.SKB[0x140 | ((R >>> 7 & 0x3) | (R >>> 8 & 0x3C))] | DES.SKB[0x180 | (R >>> 15 & 0x3F)] | DES.SKB[0x1C0 | ((R >>> 21 & 0xF) | (R >>> 22 & 0x30))]);
            sKey[j++] = (t << 16 | (s & 0xFFFF));
            s = (s >>> 16 | (t & 0xFFFF0000));
            sKey[j++] = (s << 4 | s >>> 28);
        }
        return sKey;
    }
    
    protected String stringDec(final String strCpt, final String strKey) {
        String strDes = "";
        try {
            final int intKey = strKey.getBytes().length;
            int intTemp;
            if (intKey % 8 == 0) {
                intTemp = 0;
            }
            else {
                intTemp = 1;
            }
            byte[] bytKeyAll = new byte[(intKey / 8 + intTemp) * 8];
            bytKeyAll = strKey.getBytes();
            final byte[] bytKey = new byte[8];
            if (intKey < 8) {
                for (int iob = 0; iob < 8; ++iob) {
                    bytKey[iob] = fromString("00")[0];
                }
                for (int iob = 0; iob < intKey; ++iob) {
                    bytKey[iob] = bytKeyAll[iob];
                }
            }
            else {
                for (int iob = 0; iob < 8; ++iob) {
                    bytKey[iob] = bytKeyAll[iob];
                }
            }
            final Object key = makeKey(bytKey);
            final int intCpt = strCpt.length();
            final int intBlock = intCpt / 16;
            final byte[] bytBlock = new byte[intCpt / 2];
            final String[] strBlock = new String[intBlock];
            byte[] tmp = new byte[8];
            for (int iBlock = 0; iBlock < intBlock; ++iBlock) {
                strBlock[iBlock] = strCpt.substring(iBlock * 16, iBlock * 16 + 16);
                tmp = blockDecrypt(fromString(strBlock[iBlock]), 0, key);
                for (int iob2 = 0; iob2 < 8; ++iob2) {
                    bytBlock[iBlock * 8 + iob2] = tmp[iob2];
                }
            }
            strDes = new String(bytBlock);
            strDes = strDes.trim();
        }
        catch (Exception e) {
            strDes = "error:" + e.getMessage();
        }
        return strDes;
    }
    
    protected String stringEnc(final String strSrc, final String strKey) {
        String strCpt = "";
        try {
            final int intKey = strKey.getBytes().length;
            int intTemp;
            if (intKey % 8 == 0) {
                intTemp = 0;
            }
            else {
                intTemp = 1;
            }
            byte[] bytKeyAll = new byte[(intKey / 8 + intTemp) * 8];
            bytKeyAll = strKey.getBytes();
            final byte[] bytKey = new byte[8];
            if (intKey < 8) {
                for (int iob = 0; iob < 8; ++iob) {
                    bytKey[iob] = fromString("00")[0];
                }
                for (int iob = 0; iob < intKey; ++iob) {
                    bytKey[iob] = bytKeyAll[iob];
                }
            }
            else {
                for (int iob = 0; iob < 8; ++iob) {
                    bytKey[iob] = bytKeyAll[iob];
                }
            }
            final Object key = makeKey(bytKey);
            final int intSrc = strSrc.getBytes().length;
            if (intSrc % 8 == 0) {
                intTemp = 0;
            }
            else {
                intTemp = 1;
            }
            final int intBlock = intSrc / 8 + intTemp;
            byte[] bytBlock = new byte[intBlock * 8];
            bytBlock = strSrc.getBytes();
            final byte[] oBlock = new byte[8];
            for (int iBlock = 0; iBlock < intBlock; ++iBlock) {
                int intpt;
                if (iBlock < intBlock - 1 || intSrc % 8 == 0) {
                    intpt = 8;
                }
                else {
                    intpt = intSrc % 8;
                }
                if (intpt < 8) {
                    for (int ipt = 0; ipt < 8; ++ipt) {
                        oBlock[ipt] = fromString("00")[0];
                    }
                }
                for (int iob2 = 0; iob2 < intpt; ++iob2) {
                    oBlock[iob2] = bytBlock[iBlock * 8 + iob2];
                }
                final byte[] bytCpt = blockEncrypt(oBlock, 0, key);
                strCpt = String.valueOf(strCpt) + toString(bytCpt);
            }
        }
        catch (Exception e) {
            strCpt = "error:" + e.getMessage();
        }
        return strCpt;
    }
    
    protected static final String toString(final byte[] ba) {
        final int length = ba.length;
        final char[] buf = new char[length * 2];
        int k;
        for (int i = 0, j = 0; i < length; k = ba[i++], buf[j++] = DES.HEX_DIGITS[k >>> 4 & 0xF], buf[j++] = DES.HEX_DIGITS[k & 0xF]) {}
        return new String(buf);
    }
}
