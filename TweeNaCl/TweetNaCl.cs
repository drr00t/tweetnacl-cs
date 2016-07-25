// Ported in 2016 by Adriano Ribeiro.
// Public domain.
//
// Implementation derived from TweetNaCl version 20140427.
// See for details: http://tweetnacl.cr.yp.to/

using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

public class TweetNaCl
{

    public static Int32 crypto_auth_hmacsha512256_tweet_BYTES = 32;
    public static Int32 crypto_auth_hmacsha512256_tweet_KEYBYTES = 32;
    public static Int32 BOX_PUBLIC_KEY_BYTES = 32;
    public static Int32 BOX_SECRET_KEY_BYTES = 32;
    public static Int32 BOX_SHARED_KEY_BYTES = 32;
    public static Int32 BOX_NONCE_BYTES = 24;
    public static Int32 BOX_OVERHEAD_BYTES = 16;
    public static Int32 SIGNATURE_SIZE_BYTES = 64;
    public static Int32 SIGN_PUBLIC_KEY_BYTES = 32;
    public static Int32 SIGN_SECRET_KEY_BYTES = 64;
    public static Int32 SIGN_KEYPAIR_SEED_BYTES = 32;
    public static Int32 SECRETBOX_KEY_BYTES = 32;
    public static Int32 SECRETBOX_NONCE_BYTES = 24;
    public static Int32 SECRETBOX_OVERHEAD_BYTES = 16;
    public static Int32 HASH_SIZE_BYTES = 64; // SHA-512

    private static Int32 SECRETBOX_INTERNAL_OVERHEAD_BYTES = 32;

    public class InvalidSignatureException: CryptographicException {}
    public class InvalidCipherTextException: CryptographicException {}

    private static Byte[] _0 = new Byte[16];
    private static Byte[] _9 = new Byte[32]{9,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
   
    private const Int32 GF_LEN = 16;
    private static UInt64[] GF0 = new UInt64[GF_LEN];
    private static UInt64[] GF1 = new UInt64[GF_LEN]{1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}; 

    private static UInt64[] _121665 = new UInt64[GF_LEN]{0xDB41,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    private static UInt64[] D = new UInt64[] { 0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070, 0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203 };
    private static UInt64[] D2 = new UInt64[] { 0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0, 0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406 };
    private static UInt64[] X = new UInt64[] { 0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c, 0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169 };
    private static UInt64[] Y = new UInt64[] { 0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666 };
    private static UInt64[] I = new UInt64[] { 0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43, 0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83 };

    public static UInt32 L32(UInt32 x, Int32 c) { return (x << c) | ((x&0xffffffff) >> (32 - c)); }
    
    public static UInt32 Ld32(Byte[] x, Int32 offset = 0) 
    {
        UInt32 u = x[3 + offset];
        u = (u << 8) | x[2 + offset];
        u = (u << 8) | x[1 + offset];
          return (u<<8)|x[0 + offset];
    }
    
    public static UInt64 Dl64(Byte[] x)
    {
        UInt64 u=0;
        for (var i = 0;i < 8;++i) u=(u<<8)|x[i];
        return u;
    }

    public static Int32 Vn(Byte[] x, Byte[] y, Int32 n, Int32 offset = 0)
    {
        Int32 d = 0;
        for (var i = 0; i < n; ++i) d |= x[i + offset] ^ y[i];
        return (1 & ((d - 1) >> 8)) - 1;
    }

    private static void St32(Byte[] x, UInt32 u, Int32 offset = 0)
    {
        for (var i = 0; i < 4; ++i) { x[i + offset] = (byte)u; u >>= 8; }
    }

    private void Ts64(Byte[] x, UInt64 u)
    {
        for (var i = 7; i >= 0; --i) { x[i] = (byte)u; u >>= 8; }
    }

    private static Int32 CryptoVerify16(Byte[] x, Byte[] y, Int32 offset)
    {
        return Vn(x, y, 16, offset);
    }

    private Int32 CryptoVerify32(Byte[] x, Byte[] y)
    {
        return Vn(x, y, 32);
    }

    private static void CoreSalsa(Byte[] pout, Byte[] pin, Byte[] k, Byte[] c)
    {
        UInt32[] w = new UInt32[16];
        UInt32[] x = new UInt32[16];
        UInt32[] y = new UInt32[16];
        UInt32[] t = new UInt32[4];
        
        for(var i = 0; i < 4; i++)
        {
            x[5*i] = Ld32(c, 4*i);
            x[1+i] = Ld32(k,4*i);
            x[6+i] = Ld32(pin,4*i);
            x[11+i] = Ld32(k, 16+4*i);
        }

        for (var i=0; i < 16;++i)y[i] = x[i];

        for (var i=0;i < 20;++i){
            for (var j=0;j < 4;++j){
                for (var m=0;m < 4;++m)t[m] = x[(5*j+4*m)%16];
                t[1] ^= L32(t[0]+t[3], 7);
                t[2] ^= L32(t[1]+t[0], 9);
                t[3] ^= L32(t[2]+t[1],13);
                t[0] ^= L32(t[3]+t[2],18);
                for (var m=0;m < 4;++m)w[4*j+(j+m)%4] = t[m];
            }
            for (var m=0;m < 16;++m)x[m] = w[m];
        }
    }

    private static Byte[] Sigma = Encoding.UTF8.GetBytes("expand 32-byte k");

    public static Int32 CoreSalsa20(Byte[] pout, Byte[] pin, Byte[] k, Byte[] c)
    {
        UInt32[] x = new UInt32[16];
        UInt32[] y = new UInt32[16];

        CoreSalsa(pout, pin, k, c);
        for (var i = 0; i < 16; ++i) St32(pout, x[i] + y[i], 4 * i);

        return 0;
    }

    public static Int32 CoreHSalsa20(Byte[] pout, Byte[] pin, Byte[] k, Byte[] c)
    {
        UInt32[] x = new UInt32[16];
        UInt32[] y = new UInt32[16];

        CoreSalsa(pout, pin, k, c);

        for (var i = 0; i < 16; ++i) x[i] += y[i];
        for (var i = 0; i < 4; ++i)
        {
            x[5 * i] -= Ld32(c, 4 * i);
            x[6 + i] -= Ld32(pin, 4 * i);
        }
        for (var i = 0; i < 4; ++i)
        {
            St32(pout, x[5 * i], 4 * i);
            St32(pout, x[6 + i], 16 + 4 * i);
        }

        return 0;
    }

    private static Int32 CryptoStreamSalsa20Xor(Byte[] c,Byte[] m, Int64 b, Byte[] n, Byte[] k, Int32 offset)
    {
        Byte[] z = new Byte[16];
        Byte[] x = new Byte[64];

        Int32 u = 0;
        
        if (b == 0)
        {
            return 0;
        }

        for (var i = 0; i < 16; ++i)
        {
            z[i] = 0;
        }

        for (var i = 0; i < 8; ++i)
        {
            z[i] = n[offset + i];
        }
        
        Int32 coffset = 0;
        Int32 moffset = 0;

        while (b >= 64)
        {
            CoreSalsa20(x, z, k, Sigma);
            for (var i = 0; i < 64; ++i) c[coffset + i] = (Byte)((m != null ? m[moffset + i] : 0) ^ x[i]);
            u = 1;
            for (var i = 8; i < 16; ++i)
            {
                u += 0xff & z[i];
                z[i] = (byte)u;
                u >>= 8;
            }
            b -= 64;
            coffset += 64;
            if (m != null) moffset += 64;
        }
        if (b != 0)
        {
            CoreSalsa20(x, z, k, Sigma);
            for (var i = 0; i < b; i++) c[coffset + i] = (Byte)((m != null ? m[moffset + i] : 0) ^ x[i]);
        }
        return 0;
    }

    private static Int32 CryptoStreamSalsa20(Byte[] c, Int64 d, Byte[] n, Byte[] k, Int32 noffset)
    {
        return CryptoStreamSalsa20Xor(c, null, d, n, k, noffset);
    }

    private static Int32 CryptoStream(Byte[] c, Int64 d, Byte[] n, Byte[] k)
    {
        Byte[] s = new Byte[32];
        CoreHSalsa20(s, n, k, Sigma);
        return CryptoStreamSalsa20(c, d, n, s, 16);
    }

    private static void Add1305(Int32[] h, Int32[] c)
    {
        Int32 u = 0;
        for (var j = 0; j < 17; ++j)
        {
            u += h[j] + c[j];
            h[j] = u & 255;
            u >>= 8;
        }
    }

    private static Int32[] minusp = new Int32[] { 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 252};

    private static Int32 CryptoOnetimeAuth(Byte[] pout, Int32 outOff, Byte[] m, Int32 mOff, Int64 n, Byte[] k)
    {
        Int32 l=0,s,u;
        Int32[] x = new Int32[17],r = new Int32[17],h = new Int32[17],c = new Int32[17],g = new Int32[17];

        for (var j=0;j < 17;++j)
            r[j]= h[j] = 0;

        for (var j=0;j < 16;++j)
            r[j] = 0xff & k[j];

        r[3]&=15;
        r[4]&=252;
        r[7]&=15;
        r[8]&=252;
        r[11]&=15;
        r[12]&=252;
        r[15]&=15;

        while (n > 0) {
            for (var j=0;j < 17;++j)
                c[j] = 0;

            for (var j = 0;(j < 16) && (j < n);++j)
                c[j] = 0xff & m[mOff + j];

            c[l] = 1;
            mOff += l; n -= l;
            Add1305(h,c);

            for (var i=0;i < 17;++i){
                x[i] = 0;

                for (var j=0;j < 17; ++j)
                    x[i] += h[j] * ((j <= i)? r[i - j] : 320 * r[i + 17 - j]);
            }

            for (var i=0;i < 17;++i)
                h[i] = x[i];

            u = 0;
            for (var j=0;j < 16;++j){
                u += h[j];
                h[j] = u & 255;
                u >>= 8;
            }
            u += h[16]; h[16] = u & 3;
            u = 5 * (u >> 2);

            for (var j=0;j < 16;++j){
                u += h[j];
                h[j] = u & 255;
                u >>= 8;
            }
            u += h[16]; h[16] = u;
        }

        for (var j=0;j < 17;++j)g[j] = h[j];
        Add1305(h,minusp);
        s = -(h[16] >> 7);

        for (var j=0;j < 17;++j)h[j] ^= s & (g[j] ^ h[j]);

        for (var j=0;j < 16;++j)
            c[j] = 0xff & k[j + 16];

        c[16] = 0;
        Add1305(h,c);

        for (var j=0;j < 16;++j) pout[outOff + j] = (Byte)h[j];

        return 0;
    }

    private static int CryptoOnetimeauthVerify(Byte[] h, Int32 hoffset, Byte[] m, Int64 n, Byte[] k, Int32 moffset)
    {
        Byte[] x = new Byte[16];
        CryptoOnetimeAuth(x, 0, m, moffset, n, k);
        return CryptoVerify16(h, x, hoffset);
    }
}

