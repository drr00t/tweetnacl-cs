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
    private static Int64[] GF0 = new Int64[GF_LEN];
    private static Int64[] GF1 = new Int64[GF_LEN]{1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

    private static Int64[] _121665 = new Int64[GF_LEN] { 0xDB41, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    private static Int64[] D = new Int64[] { 0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070, 0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203 };
    private static Int64[] D2 = new Int64[] { 0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0, 0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406 };
    private static Int64[] X = new Int64[] { 0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c, 0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169 };
    private static Int64[] Y = new Int64[] { 0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666 };
    private static Int64[] I = new Int64[] { 0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43, 0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83 };

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


    private static void St32(Byte[] x, UInt32 u, Int32 offset = 0)
    {
        for (var i = 0; i < 4; ++i) { x[i + offset] = (Byte)u; u >>= 8; }
    }

    private void Ts64(Byte[] x, UInt64 u, Int32 offset = 0)
    {
        for (var i = 7; i >= 0; --i) { x[i + offset] = (Byte)u; u >>= 8; }
    }
    
    public static Int32 Vn(Byte[] x, Byte[] y, Int32 n, Int32 xOffset = 0)
    {
        Int32 d = 0;
        for (var i = 0; i < n; ++i) d |= x[i + xOffset] ^ y[i];
        return (1 & ((d - 1) >> 8)) - 1;
    }

    private static Int32 CryptoVerify16(Byte[] x, Byte[] y, Int32 xOffset)
    {
        return Vn(x, y, 16, xOffset);
    }

    private static Int32 CryptoVerify32(Byte[] x, Byte[] y)
    {
        return Vn(x, y, 32);
    }

    private static void Core(Byte[] pout, Byte[] pin, Byte[] k, Byte[] c)
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

        for (var i = 0; i < 16; ++i)
        {
            y[i] = x[i];
        }

        for (var i=0;i < 20;++i)
        {
            for (var j=0;j < 4;++j)
            {
                for (var m = 0; m < 4; ++m)
                {
                    t[m] = x[(5 * j + 4 * m) % 16];
                }
                
                t[1] ^= L32(t[0]+t[3], 7);
                t[2] ^= L32(t[1]+t[0], 9);
                t[3] ^= L32(t[2]+t[1],13);
                t[0] ^= L32(t[3]+t[2],18);
                
                for (var m = 0; m < 4; ++m)
                {
                    w[4 * j + (j + m) % 4] = t[m];
                }
            }

            for (var m = 0; m < 16; ++m)
            {
                x[m] = w[m];
            }
        }
    }

    public static Int32 CryptoCoreSalsa20(Byte[] pout, Byte[] pin, Byte[] k, Byte[] c)
    {
        UInt32[] x = new UInt32[16];
        UInt32[] y = new UInt32[16];

        Core(pout, pin, k, c);

        for (var i = 0; i < 16; ++i)
        {
            St32(pout, x[i] + y[i], 4 * i);
        }

        return 0;
    }

    public static Int32 CryptoCoreHSalsa20(Byte[] pout, Byte[] pin, Byte[] k, Byte[] c)
    {
        UInt32[] x = new UInt32[16];
        UInt32[] y = new UInt32[16];

        Core(pout, pin, k, c);

        for (var i = 0; i < 16; ++i)
        {
            x[i] += y[i];
        }

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

    private static Byte[] Sigma = Encoding.UTF8.GetBytes("expand 32-byte k");

    private static Int32 CryptoStreamSalsa20Xor(Byte[] c, Byte[] m, Int64 b, Byte[] n, Int32 nOffset, Byte[] k)
    {
        Byte[] z = new Byte[16];
        Byte[] x = new Byte[64];

        UInt32 u = 0;
        
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
            z[i] = n[nOffset + i];
        }
        
        Int32 cOffset = 0;
        Int32 mOffset = 0;

        while (b >= 64)
        {
            CryptoCoreSalsa20(x, z, k, Sigma);
            for (var i = 0; i < 64; ++i)
            {
                c[cOffset + i] = (Byte)((m != null ? m[mOffset + i] : 0) ^ x[i]);
            }

            u = 1;
            for (var i = 8; i < 16; ++i)
            {
                u += (UInt32) 0xff & z[i];
                z[i] = (Byte)u;
                u >>= 8;
            }

            b -= 64;
            cOffset += 64;
            if (m != null)
            {
                mOffset += 64;
            }
        }

        if (b != 0)
        {
            CryptoCoreSalsa20(x, z, k, Sigma);
            
            for (var i = 0; i < b; i++)
            {
                c[cOffset + i] = (Byte)((m != null ? m[mOffset + i] : 0) ^ x[i]);
            }
        }

        return 0;
    }

    private static Int32 CryptoStreamSalsa20(Byte[] c, Int64 d, Byte[] n, Int32 nOffset, Byte[] k)
    {
        return CryptoStreamSalsa20Xor(c, null, d, n, nOffset, k);
    }

    private static Int32 CryptoStream(Byte[] c, Int64 d, Byte[] n, Byte[] k)
    {
        Byte[] s = new Byte[32];

        CryptoCoreHSalsa20(s, n, k, Sigma);
        return CryptoStreamSalsa20(c, d, n, 16, s);
    }

    private static Int32 CryptoStreamXor(Byte[] c, Byte[] m, Int64 d, Byte[] n, Byte[] k)
    {
        Byte[] s = new Byte[32];
        
        CryptoCoreHSalsa20(s, n, k, Sigma);

        return CryptoStreamSalsa20Xor(c, m, d, n, 16, s);

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

    private static Int32[] Minusp = new Int32[17] { 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 252};

    private static Int32 CryptoOnetimeAuth(Byte[] pout, Int32 outOffset, Byte[] m, Int64 mOffset, Int64 n, Byte[] k)
    {
        Int32 l=0, u=0, s=0;
        Int32[] x = new Int32[17], r = new Int32[17], h = new Int32[17], c = new Int32[17], g = new Int32[17];

        for (var j=0;j < 17;++j)
        {
            r[j] = 0;
            h[j] = 0;
        }


        for (var j=0;j < 16;++j)
        {
            r[j] = 0xff & k[j];
        }            

        r[3]&=15;
        r[4]&=252;
        r[7]&=15;
        r[8]&=252;
        r[11]&=15;
        r[12]&=252;
        r[15]&=15;

        while (n > 0) 
        {
            for (var j=0;j < 17;++j)
                c[j] = 0;

            for (Int64 j = 0; (j < 16) && (j < n); ++j)
                c[j] = 0xff & m[mOffset + j];

            c[l] = 1;
            mOffset += (Int64)l; n -= (Int64)l;
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

        for (var j = 0; j < 17; ++j)
        {
            g[j] = h[j];
        }

        Add1305(h,Minusp);
        s = -(h[16] >> 7);

        for (var j = 0; j < 17; ++j)
        {
            h[j] ^= s & (g[j] ^ h[j]);
        }

        for (var j=0;j < 16;++j)
        {
            c[j] = 0xff & k[j + 16];
        }
            

        c[16] = 0;
        Add1305(h,c);

        for (var j = 0; j < 16; ++j)
        {
            pout[outOffset + j] = (Byte)h[j];
        }

        return 0;
    }

    private static Int32 CryptoOnetimeauthVerify(Byte[] h, Int32 hoffset, Byte[] m, Int64 mOffset, Int64 n, Byte[] k)
    {
        Byte[] x = new Byte[16];
        CryptoOnetimeAuth(x, 0, m, mOffset, n, k);
        return CryptoVerify16(h, x, hoffset);
    }

    private static Int32 CryptoSecretBox(Byte[] c, Byte[] m, Int64 d, Byte[] n, Byte[] k)
    {
        if (d < 32)
        {
            return -1;
        }

        CryptoStreamXor(c, m, d, n, k);
        CryptoOnetimeAuth(c, 16, c, 32, d - 32, c);
        
        for (var i = 0; i < 16; ++i)
        {
            c[i] = 0;
        }

        return 0;
    }

    private static Int32 CryptoSecretBoxOpen(Byte[] m, Byte[] c, Int64 d, Byte[] n, Byte[] k)
    {
        Byte[] x = new Byte[32];

        if (d < 32)
        {
            return -1;
        }

        CryptoStream(x, 32, n, k);

        if (CryptoOnetimeauthVerify(c, 16, c, 32, d - 32, x) != 0)
        {
            return -1;
        }

        CryptoStreamXor(m, c, d, n, k);

        for (var i = 0; i < 32; ++i)
        {
            m[i] = 0;
        }

        return 0;
    }

    private static void Set25519(Int64[] /*gf*/ r, Int64[] /*gf*/ a)
    {
        for (var i = 0; i < 16; ++i)
        {
            r[i] = a[i];
        }
    }

    private static void Car25519(Int64[] /*gf*/ o, Int32 oOffset)
    {
        for (var i = 0; i < 16; ++i)
        {
            o[oOffset + i] += (1 << 16);
            Int64 c = o[oOffset + i] >> 16;
            o[oOffset + (i + 1) * (i < 15 ? 1 : 0)] += c - 1 + 37 * (c - 1) * (i == 15 ? 1 : 0);
            o[oOffset + i] -= c << 16;
        }
    }

    private static void Sel25519(Int64[] /*gf*/ p, Int64[] /*gf*/ q, Int32 b)
    {
        Int64 t, c = ~(b - 1);
        for (var i = 0; i < 16; ++i)
        {
            t = c & (p[i] ^ q[i]);
            p[i] ^= t;
            q[i] ^= t;
        }
    }

    private static void Pack25519(Byte[] o, Int64[] /*gf*/ n, Int32 nOffset)
    {
        Int32 b = 0;
        Int64[] /*gf*/ m = new Int64[GF_LEN], t = new Int64[GF_LEN];

        for (var i = 0; i < 16; ++i)
        {
            t[i] = n[nOffset + i];
        }
        
        Car25519(t, 0);
        Car25519(t, 0);
        Car25519(t, 0);
        
        for (var j = 0; j < 2; ++j)
        {
            m[0] = t[0] - 0xffed;

            for (var i = 1; i < 15; i++)
            {
                m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
                m[i - 1] &= 0xffff;
            }

            m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
            b = (Int32)((m[15] >> 16) & 1);
            m[14] &= 0xffff;
            Sel25519(t, m, 1 - b);
        }

        for (var i = 0; i < 16; ++i)
        {
            o[2 * i] = (Byte)t[i];
            o[2 * i + 1] = (Byte)(t[i] >> 8);
        }
    }

    private static Int32 Neq25519(Int64[] /*gf*/ a, Int64[] /*gf*/ b)
    {
        Byte[] c = new Byte[32], d = new Byte[32];
        Pack25519(c, a, 0);
        Pack25519(d, b, 0);
        return CryptoVerify32(c, d);
    }

    private static Byte Par25519(Int64[] /*gf*/ a)
    {
        Byte[] d = new Byte[32];

        Pack25519(d, a, 0);

        return (Byte)(d[0] & 1);
    }

    private static void Unpack25519(Int64[] /*gf*/ o, Byte[] n)
    {
        for (var i = 0; i < 16; ++i)
        {
            o[i] = (0xff & n[2 * i]) + ((0xffL & n[2 * i + 1]) << 8);
        }
            
        o[15] &= 0x7fff;
    }

    private static void A(Int64[] /*gf*/ o, Int64[] /*gf*/ a, Int64[] /*gf*/ b)
    {
        for (var i = 0; i < 16; ++i)
        {
            o[i] = a[i] + b[i];
        }
    }

    private static void Z(Int64[] /*gf*/ o, Int64[] /*gf*/ a, Int64[] /*gf*/ b)
    {
        for (var i = 0; i < 16; ++i)
        {
            o[i] = a[i] - b[i];
        }
    }

    private static void M(Int64[] /*gf*/ o, Int32 oOffset, Int64[] /*gf*/ a, Int32 aOffset, Int64[] /*gf*/ b, Int32 bOffset)
    {
        Int64[] t = new Int64[31];

        for (var i = 0; i < 31; ++i)
        {
            t[i] = 0;
        }

        for (var i = 0; i < 16; ++i)
        {
            for (var j = 0; j < 16; ++j)
            {
                t[i + j] += a[aOffset + i] * b[bOffset + j];
            }
        }

        for (var i = 0; i < 15; ++i)
        {
            t[i] += 38 * t[i + 16];
        }

        for (var i = 0; i < 16; ++i)
        {
            o[oOffset + i] = t[i];
        }

        Car25519(o, oOffset);
        Car25519(o, oOffset);
    }

    private static void S(Int64[] /*gf*/ o, Int64[] /*gf*/ a)
    {
        M(o, 0, a, 0, a, 0);
    }

    private static void Inv25519(Int64[] /*gf*/ o, Int32 oOffset, Int64[] /*gf*/ i, Int32 iOffset)
    {
        Int64[] /*gf*/ c = new Int64[GF_LEN];

        for (var a = 0; a < 16; ++a)
        {
            c[a] = i[iOffset + a];
        }

        for (var a = 253; a >= 0; a--)
        {
            S(c, c);
            if (a != 2 && a != 4)
            {
                M(c, 0, c, 0, i, iOffset);
            }
        }

        for (var a = 0; a < 16; ++a)
        {
            o[oOffset + a] = c[a];
        }
    }

    private static void Pow2523(Int64[] /*gf*/ o, Int64[] /*gf*/ i)
    {
        Int64[] /*gf*/ c = new Int64[GF_LEN];

        for (var a = 0; a < 16; ++a)
        {
            c[a] = i[a];
        }

        for (var a = 250; a >= 0; a--)
        {
            S(c, c);

            if (a != 1)
            {
                M(c, 0, c, 0, i, 0);
            }
        }

        for (var a = 0; a < 16; ++a)
        {
            o[a] = c[a];
        }
    }

    private static Int32 CryptoScalarmult(Byte[] q, Byte[] n, Byte[] p)
    {
        Byte[] z = new Byte[32];
        Int64[] x = new Int64[80];
        Int32 r;
        Int64[] /*gf*/ a = new Int64[GF_LEN], b = new Int64[GF_LEN], c = new Int64[GF_LEN],
                d = new Int64[GF_LEN], e = new Int64[GF_LEN], f = new Int64[GF_LEN];

        for (var i = 0; i < 31; ++i)
        {
            z[i] = n[i];
        }

        z[31] = (Byte)((n[31] & 127) | 64);
        z[0] &= 248;

        Unpack25519(x, p);
        
        for (var i = 0; i < 16; ++i)
        {
            b[i] = x[i];
            d[i] = a[i] = c[i] = 0;
        }

        a[0] = d[0] = 1;

        for (var i = 254; i >= 0; --i)
        {
            r = ((0xff & z[i >> 3]) >> (i & 7)) & 1;
            Sel25519(a, b, r);
            Sel25519(c, d, r);
            A(e, a, c);
            Z(a, a, c);
            A(c, b, d);
            Z(b, b, d);
            S(d, e);
            S(f, a);
            M(a, 0, c, 0, a, 0);
            M(c, 0, b, 0, e, 0);
            A(e, a, c);
            Z(a, a, c);
            S(b, a);
            Z(c, d, f);
            M(a, 0, c, 0, _121665, 0);
            A(a, a, d);
            M(c, 0, c, 0, a, 0);
            M(a, 0, d, 0, f, 0);
            M(d, 0, b, 0, x, 0);
            S(b, e);
            Sel25519(a, b, r);
            Sel25519(c, d, r);
        }
        for (var i = 0; i < 16; ++i)
        {
            x[i + 16] = a[i];
            x[i + 32] = c[i];
            x[i + 48] = b[i];
            x[i + 64] = d[i];
        }

        Inv25519(x, 32, x, 32);

        M(x, 16, x, 16, x, 32);

        Pack25519(q, x, 16);

        return 0;
    }

    private static Int32 CryptoScalarmultBase(Byte[] q, Byte[] n)
    { 
      return CryptoScalarmult(q,n,_9);
    }

    private static Int32 CryptoBoxKeypair(Byte[] y, Byte[] x)
    {
        RandomBytes(x);
        return CryptoScalarmultBase(y, x);
    }

    private static Int32 CryptoBoxBeforenm(Byte[] k, Byte[] y, Byte[] x)
    {
        Byte[] s = new Byte[32];
        CryptoScalarmult(s, x, y);
        return CryptoCoreHSalsa20(k, _0, s, Sigma);
    }

    private static Int32 CryptoBoxAfternm(Byte[] c, Byte[] m, Int64 d, Byte[] n, Byte[] k)
    {
        return CryptoSecretBox(c, m, d, n, k);
    }

    private static Int32 CryptoBoxOpenAfternm(Byte[] m, Byte[] c, Int64 d, Byte[] n, Byte[] k)
    {
        return CryptoSecretBoxOpen(m, c, d, n, k);
    }

    private static Int32 CryptoBox(Byte[] c, Byte[] m, Int64 d, Byte[] nonce, Byte[] theirPublicBoxingKey, Byte[] ourSecretBoxingKey)
    {
        Byte[] k = new Byte[32];
        CryptoBoxBeforenm(k, theirPublicBoxingKey, ourSecretBoxingKey);
        return CryptoBoxAfternm(c, m, d, nonce, k);
    }
    
    private static Int32 CryptoBoxOpen(Byte[] m, Byte[] c, Int64 d, Byte[] n, Byte[] y, Byte[] x)
    {
        Byte[] k = new Byte[32];
        CryptoBoxBeforenm(k, y, x);
        return CryptoBoxOpenAfternm(m, c, d, n, k);
    }

    private static Int64 R(Int64 x,int c) { return (x >> c) | (x << (64 - c)); }
    private static Int64 Ch(Int64 x,Int64 y,Int64 z) { return (x & y) ^ (~x & z); }
    private static Int64 Maj(Int64 x,Int64 y,Int64 z) { return (x & y) ^ (x & z) ^ (y & z); }
    private static Int64 Sigma0(Int64 x) { return R(x,28) ^ R(x,34) ^ R(x,39); }
    private static Int64 Sigma1(Int64 x) { return R(x,14) ^ R(x,18) ^ R(x,41); }
    private static Int64 sigma0(Int64 x) { return R(x, 1) ^ R(x, 8) ^ (x >> 7); }
    private static Int64 sigma1(Int64 x) { return R(x,19) ^ R(x,61) ^ (x >> 6); }

    private static const UInt64[] K = new UInt64[80]
    {
      0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
      0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
      0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
      0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
      0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
      0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
      0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
      0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
      0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
      0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
      0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
      0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
      0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
      0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
      0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
      0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
      0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
      0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
      0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
      0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
    };

    // I need replace taht because of GPL license
    //
    /* Ported from the original C by Ian Preston and Chris Boddy
     * crypto_hash() is ported from TweetNaCl.js
     * Released under GPL 2
     */
    private static Int32 CryptoHash(Byte[] pout, Byte[] m, Int32 n) {
        UInt32[] hh = new UInt32[8], hl = new UInt32[8];
        Byte[] x = new Byte[256];
        Int32 b = n;

        hh[0] = 0x6a09e667;
        hh[1] = 0xbb67ae85;
        hh[2] = 0x3c6ef372;
        hh[3] = 0xa54ff53a;
        hh[4] = 0x510e527f;
        hh[5] = 0x9b05688c;
        hh[6] = 0x1f83d9ab;
        hh[7] = 0x5be0cd19;

        hl[0] = 0xf3bcc908;
        hl[1] = 0x84caa73b;
        hl[2] = 0xfe94f82b;
        hl[3] = 0x5f1d36f1;
        hl[4] = 0xade682d1;
        hl[5] = 0x2b3e6c1f;
        hl[6] = 0xfb41bd6b;
        hl[7] = 0x137e2179;

        CryptoHashBlocksHl(hh, hl, m, n);
        n %= 128;

        for (var i = 0; i < n; i++) x[i] = m[b-n+i];
        x[n] = (Byte)128;

        n = 256-128*(n<112?1:0);
        x[n-9] = 0;
        Jsts64(x, n - 8, (b / 0x20000000), b << 3);
        CryptoHashBlocksHl(hh, hl, x, n);

        for (var i = 0; i < 8; i++) Jsts64(pout, 8 * i, hh[i], hl[i]);

        return 0;
    }

    private static void Jsts64(byte[] x, int i, int h, int l) {
        x[i]   = (Byte)(h >> 24);
        x[i+1] = (Byte)(h >> 16);
        x[i+2] = (Byte)(h >>  8);
        x[i+3] = (Byte)h;
        x[i+4] = (Byte)(l >> 24);
        x[i+5] = (Byte)(l >> 16);
        x[i+6] = (Byte)(l >>  8);
        x[i+7] = (Byte)l;
    }

    private static UInt32[] jsK = new UInt32[]{
            0x428a2f98, 0xd728ae22, 0x71374491, 0x23ef65cd,
            0xb5c0fbcf, 0xec4d3b2f, 0xe9b5dba5, 0x8189dbbc,
            0x3956c25b, 0xf348b538, 0x59f111f1, 0xb605d019,
            0x923f82a4, 0xaf194f9b, 0xab1c5ed5, 0xda6d8118,
            0xd807aa98, 0xa3030242, 0x12835b01, 0x45706fbe,
            0x243185be, 0x4ee4b28c, 0x550c7dc3, 0xd5ffb4e2,
            0x72be5d74, 0xf27b896f, 0x80deb1fe, 0x3b1696b1,
            0x9bdc06a7, 0x25c71235, 0xc19bf174, 0xcf692694,
            0xe49b69c1, 0x9ef14ad2, 0xefbe4786, 0x384f25e3,
            0x0fc19dc6, 0x8b8cd5b5, 0x240ca1cc, 0x77ac9c65,
            0x2de92c6f, 0x592b0275, 0x4a7484aa, 0x6ea6e483,
            0x5cb0a9dc, 0xbd41fbd4, 0x76f988da, 0x831153b5,
            0x983e5152, 0xee66dfab, 0xa831c66d, 0x2db43210,
            0xb00327c8, 0x98fb213f, 0xbf597fc7, 0xbeef0ee4,
            0xc6e00bf3, 0x3da88fc2, 0xd5a79147, 0x930aa725,
            0x06ca6351, 0xe003826f, 0x14292967, 0x0a0e6e70,
            0x27b70a85, 0x46d22ffc, 0x2e1b2138, 0x5c26c926,
            0x4d2c6dfc, 0x5ac42aed, 0x53380d13, 0x9d95b3df,
            0x650a7354, 0x8baf63de, 0x766a0abb, 0x3c77b2a8,
            0x81c2c92e, 0x47edaee6, 0x92722c85, 0x1482353b,
            0xa2bfe8a1, 0x4cf10364, 0xa81a664b, 0xbc423001,
            0xc24b8b70, 0xd0f89791, 0xc76c51a3, 0x0654be30,
            0xd192e819, 0xd6ef5218, 0xd6990624, 0x5565a910,
            0xf40e3585, 0x5771202a, 0x106aa070, 0x32bbd1b8,
            0x19a4c116, 0xb8d2d0c8, 0x1e376c08, 0x5141ab53,
            0x2748774c, 0xdf8eeb99, 0x34b0bcb5, 0xe19b48a8,
            0x391c0cb3, 0xc5c95a63, 0x4ed8aa4a, 0xe3418acb,
            0x5b9cca4f, 0x7763e373, 0x682e6ff3, 0xd6b2b8a3,
            0x748f82ee, 0x5defb2fc, 0x78a5636f, 0x43172f60,
            0x84c87814, 0xa1f0ab72, 0x8cc70208, 0x1a6439ec,
            0x90befffa, 0x23631e28, 0xa4506ceb, 0xde82bde9,
            0xbef9a3f7, 0xb2c67915, 0xc67178f2, 0xe372532b,
            0xca273ece, 0xea26619c, 0xd186b8c7, 0x21c0c207,
            0xeada7dd6, 0xcde0eb1e, 0xf57d4f7f, 0xee6ed178,
            0x06f067aa, 0x72176fba, 0x0a637dc5, 0xa2c898a6,
            0x113f9804, 0xbef90dae, 0x1b710b35, 0x131c471b,
            0x28db77f5, 0x23047d84, 0x32caab7b, 0x40c72493,
            0x3c9ebe0a, 0x15c9bebc, 0x431d67c4, 0x9c100d4c,
            0x4cc5d4be, 0xcb3e42b6, 0x597f299c, 0xfc657e2a,
            0x5fcb6fab, 0x3ad6faec, 0x6c44198c, 0x4a475817
    };

    private static Int32 CryptoHashBlocksHl(Int32[] hh, Int32[] hl, Byte[] m, Int32 n) 
    {
        Int32[] wh = new Int32[16], wl = new Int32[16];
        Int32 bh0, bh1, bh2, bh3, bh4, bh5, bh6, bh7,
                bl0, bl1, bl2, bl3, bl4, bl5, bl6, bl7,
                th, tl, h, l, a, b, c, d;

        Int32 ah0 = hh[0],
                ah1 = hh[1],
                ah2 = hh[2],
                ah3 = hh[3],
                ah4 = hh[4],
                ah5 = hh[5],
                ah6 = hh[6],
                ah7 = hh[7],

                al0 = hl[0],
                al1 = hl[1],
                al2 = hl[2],
                al3 = hl[3],
                al4 = hl[4],
                al5 = hl[5],
                al6 = hl[6],
                al7 = hl[7];

        Int32 pos = 0;
        while (n >= 128) {
            for (var i = 0; i < 16; i++) {
                j = 8 * i + pos;
                wh[i] = ((m[j+0] & 0xff) << 24) | ((m[j+1] & 0xff) << 16) | ((m[j+2] & 0xff) << 8) | (m[j+3] & 0xff);
                wl[i] = ((m[j+4] & 0xff) << 24) | ((m[j+5] & 0xff) << 16) | ((m[j+6] & 0xff) << 8) | (m[j+7] & 0xff);
            }
            for (var i = 0; i < 80; i++) {
                bh0 = ah0;
                bh1 = ah1;
                bh2 = ah2;
                bh3 = ah3;
                bh4 = ah4;
                bh5 = ah5;
                bh6 = ah6;
                bh7 = ah7;

                bl0 = al0;
                bl1 = al1;
                bl2 = al2;
                bl3 = al3;
                bl4 = al4;
                bl5 = al5;
                bl6 = al6;
                bl7 = al7;

                // add
                h = ah7;
                l = al7;

                a = l & 0xffff; b = l >>> 16;
                c = h & 0xffff; d = h >>> 16;

                // Sigma1
                h = ((ah4 >>> 14) | (al4 << (32-14))) ^ ((ah4 >>> 18) | (al4 << (32-18))) ^ ((al4 >>> (41-32)) | (ah4 << (32-(41-32))));
                l = ((al4 >>> 14) | (ah4 << (32-14))) ^ ((al4 >>> 18) | (ah4 << (32-18))) ^ ((ah4 >>> (41-32)) | (al4 << (32-(41-32))));

                a += l & 0xffff; b += l >>> 16;
                c += h & 0xffff; d += h >>> 16;

                // Ch
                h = (ah4 & ah5) ^ (~ah4 & ah6);
                l = (al4 & al5) ^ (~al4 & al6);

                a += l & 0xffff; b += l >>> 16;
                c += h & 0xffff; d += h >>> 16;

                // K
                h = jsK[i*2];
                l = jsK[i*2+1];

                a += l & 0xffff; b += l >>> 16;
                c += h & 0xffff; d += h >>> 16;

                // w
                h = wh[i%16];
                l = wl[i%16];

                a += l & 0xffff; b += l >>> 16;
                c += h & 0xffff; d += h >>> 16;

                b += a >>> 16;
                c += b >>> 16;
                d += c >>> 16;

                th = c & 0xffff | d << 16;
                tl = a & 0xffff | b << 16;

                // add
                h = th;
                l = tl;

                a = l & 0xffff; b = l >>> 16;
                c = h & 0xffff; d = h >>> 16;

                // Sigma0
                h = ((ah0 >>> 28) | (al0 << (32-28))) ^ ((al0 >>> (34-32)) | (ah0 << (32-(34-32)))) ^ ((al0 >>> (39-32)) | (ah0 << (32-(39-32))));
                l = ((al0 >>> 28) | (ah0 << (32-28))) ^ ((ah0 >>> (34-32)) | (al0 << (32-(34-32)))) ^ ((ah0 >>> (39-32)) | (al0 << (32-(39-32))));

                a += l & 0xffff; b += l >>> 16;
                c += h & 0xffff; d += h >>> 16;

                // Maj
                h = (ah0 & ah1) ^ (ah0 & ah2) ^ (ah1 & ah2);
                l = (al0 & al1) ^ (al0 & al2) ^ (al1 & al2);

                a += l & 0xffff; b += l >>> 16;
                c += h & 0xffff; d += h >>> 16;

                b += a >>> 16;
                c += b >>> 16;
                d += c >>> 16;

                bh7 = (c & 0xffff) | (d << 16);
                bl7 = (a & 0xffff) | (b << 16);

                // add
                h = bh3;
                l = bl3;

                a = l & 0xffff; b = l >>> 16;
                c = h & 0xffff; d = h >>> 16;

                h = th;
                l = tl;

                a += l & 0xffff; b += l >>> 16;
                c += h & 0xffff; d += h >>> 16;

                b += a >>> 16;
                c += b >>> 16;
                d += c >>> 16;

                bh3 = (c & 0xffff) | (d << 16);
                bl3 = (a & 0xffff) | (b << 16);

                ah1 = bh0;
                ah2 = bh1;
                ah3 = bh2;
                ah4 = bh3;
                ah5 = bh4;
                ah6 = bh5;
                ah7 = bh6;
                ah0 = bh7;

                al1 = bl0;
                al2 = bl1;
                al3 = bl2;
                al4 = bl3;
                al5 = bl4;
                al6 = bl5;
                al7 = bl6;
                al0 = bl7;

                if (i%16 == 15) {
                    for (var j = 0; j < 16; j++) {
                        // add
                        h = wh[j];
                        l = wl[j];

                        a = l & 0xffff; b = l >>> 16;
                        c = h & 0xffff; d = h >>> 16;

                        h = wh[(j+9)%16];
                        l = wl[(j+9)%16];

                        a += l & 0xffff; b += l >>> 16;
                        c += h & 0xffff; d += h >>> 16;

                        // sigma0
                        th = wh[(j+1)%16];
                        tl = wl[(j+1)%16];
                        h = ((th >>> 1) | (tl << (32-1))) ^ ((th >>> 8) | (tl << (32-8))) ^ (th >>> 7);
                        l = ((tl >>> 1) | (th << (32-1))) ^ ((tl >>> 8) | (th << (32-8))) ^ ((tl >>> 7) | (th << (32-7)));

                        a += l & 0xffff; b += l >>> 16;
                        c += h & 0xffff; d += h >>> 16;

                        // sigma1
                        th = wh[(j+14)%16];
                        tl = wl[(j+14)%16];
                        h = ((th >>> 19) | (tl << (32-19))) ^ ((tl >>> (61-32)) | (th << (32-(61-32)))) ^ (th >>> 6);
                        l = ((tl >>> 19) | (th << (32-19))) ^ ((th >>> (61-32)) | (tl << (32-(61-32)))) ^ ((tl >>> 6) | (th << (32-6)));

                        a += l & 0xffff; b += l >>> 16;
                        c += h & 0xffff; d += h >>> 16;

                        b += a >>> 16;
                        c += b >>> 16;
                        d += c >>> 16;

                        wh[j] = (c & 0xffff) | (d << 16);
                        wl[j] = (a & 0xffff) | (b << 16);
                    }
                }
            }

            // add
            h = ah0;
            l = al0;

            a = l & 0xffff; b = l >>> 16;
            c = h & 0xffff; d = h >>> 16;

            h = hh[0];
            l = hl[0];

            a += l & 0xffff; b += l >>> 16;
            c += h & 0xffff; d += h >>> 16;

            b += a >>> 16;
            c += b >>> 16;
            d += c >>> 16;

            hh[0] = ah0 = (c & 0xffff) | (d << 16);
            hl[0] = al0 = (a & 0xffff) | (b << 16);

            h = ah1;
            l = al1;

            a = l & 0xffff; b = l >>> 16;
            c = h & 0xffff; d = h >>> 16;

            h = hh[1];
            l = hl[1];

            a += l & 0xffff; b += l >>> 16;
            c += h & 0xffff; d += h >>> 16;

            b += a >>> 16;
            c += b >>> 16;
            d += c >>> 16;

            hh[1] = ah1 = (c & 0xffff) | (d << 16);
            hl[1] = al1 = (a & 0xffff) | (b << 16);

            h = ah2;
            l = al2;

            a = l & 0xffff; b = l >>> 16;
            c = h & 0xffff; d = h >>> 16;

            h = hh[2];
            l = hl[2];

            a += l & 0xffff; b += l >>> 16;
            c += h & 0xffff; d += h >>> 16;

            b += a >>> 16;
            c += b >>> 16;
            d += c >>> 16;

            hh[2] = ah2 = (c & 0xffff) | (d << 16);
            hl[2] = al2 = (a & 0xffff) | (b << 16);

            h = ah3;
            l = al3;

            a = l & 0xffff; b = l >>> 16;
            c = h & 0xffff; d = h >>> 16;

            h = hh[3];
            l = hl[3];

            a += l & 0xffff; b += l >>> 16;
            c += h & 0xffff; d += h >>> 16;

            b += a >>> 16;
            c += b >>> 16;
            d += c >>> 16;

            hh[3] = ah3 = (c & 0xffff) | (d << 16);
            hl[3] = al3 = (a & 0xffff) | (b << 16);

            h = ah4;
            l = al4;

            a = l & 0xffff; b = l >>> 16;
            c = h & 0xffff; d = h >>> 16;

            h = hh[4];
            l = hl[4];

            a += l & 0xffff; b += l >>> 16;
            c += h & 0xffff; d += h >>> 16;

            b += a >>> 16;
            c += b >>> 16;
            d += c >>> 16;

            hh[4] = ah4 = (c & 0xffff) | (d << 16);
            hl[4] = al4 = (a & 0xffff) | (b << 16);

            h = ah5;
            l = al5;

            a = l & 0xffff; b = l >>> 16;
            c = h & 0xffff; d = h >>> 16;

            h = hh[5];
            l = hl[5];

            a += l & 0xffff; b += l >>> 16;
            c += h & 0xffff; d += h >>> 16;

            b += a >>> 16;
            c += b >>> 16;
            d += c >>> 16;

            hh[5] = ah5 = (c & 0xffff) | (d << 16);
            hl[5] = al5 = (a & 0xffff) | (b << 16);

            h = ah6;
            l = al6;

            a = l & 0xffff; b = l >>> 16;
            c = h & 0xffff; d = h >>> 16;

            h = hh[6];
            l = hl[6];

            a += l & 0xffff; b += l >>> 16;
            c += h & 0xffff; d += h >>> 16;

            b += a >>> 16;
            c += b >>> 16;
            d += c >>> 16;

            hh[6] = ah6 = (c & 0xffff) | (d << 16);
            hl[6] = al6 = (a & 0xffff) | (b << 16);

            h = ah7;
            l = al7;

            a = l & 0xffff; b = l >>> 16;
            c = h & 0xffff; d = h >>> 16;

            h = hh[7];
            l = hl[7];

            a += l & 0xffff; b += l >>> 16;
            c += h & 0xffff; d += h >>> 16;

            b += a >>> 16;
            c += b >>> 16;
            d += c >>> 16;

            hh[7] = ah7 = (c & 0xffff) | (d << 16);
            hl[7] = al7 = (a & 0xffff) | (b << 16);

            pos += 128;
            n -= 128;
        }

        return n;
    }

    public static void RandomBytes(Byte[] d)
    {
        using(RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
        {
            rng.GetBytes(d);
        }
    }
}

