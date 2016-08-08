//This is free and unencumbered software released into the public domain.

//Anyone is free to copy, modify, publish, use, compile, sell, or
//distribute this software, either in source code form or as a compiled
//binary, for any purpose, commercial or non-commercial, and by any
//means.

//In jurisdictions that recognize copyright laws, the author or authors
//of this software dedicate any and all copyright interest in the
//software to the public domain. We make this dedication for the benefit
//of the public at large and to the detriment of our heirs and
//successors. We intend this dedication to be an overt act of
//relinquishment in perpetuity of all present and future rights to this
//software under copyright law.

//THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
//EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
//MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
//IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
//OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
//ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
//OTHER DEALINGS IN THE SOFTWARE.

//For more information, please refer to <http://unlicense.org/>




using Nacl;
using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;


namespace NaCl.Tests
{
    [TestFixture]
    public class TweetNaClTests
    {
        [Test]
        public void TestForRandomBytesGeneration()
        {
            Byte[] b200 = new Byte[200];
            Byte[] b100 = new Byte[100];
            Byte[] b10 = new Byte[10];
            Byte[] b1 = new Byte[1];

            TweetNaCl.RandomBytes(b10);
            TweetNaCl.RandomBytes(b1);
            TweetNaCl.RandomBytes(b100);
            TweetNaCl.RandomBytes(b200);

            String text10 =  Encoding.ASCII.GetString(b10);
            String text100 = Encoding.ASCII.GetString(b100);
            String text200 = Encoding.ASCII.GetString(b200);
            String text1 = Encoding.ASCII.GetString(b1);

            Assert.AreEqual(1, text1.Length);
            Assert.AreEqual(10, text10.Length);
            Assert.AreEqual(100, text100.Length);
            Assert.AreEqual(200, text200.Length);
        }

        [Test]
        public void TestForCryptoScalarmult()
        {
            Byte[] n = new Byte[TweetNaCl.SCALARMULT_BYTES];
            Byte[] p = new Byte[TweetNaCl.SCALARMULT_SCALARBYTES];
            Byte[] q = new Byte[TweetNaCl.SCALARMULT_BYTES];

            TweetNaCl.RandomBytes(n);
            TweetNaCl.RandomBytes(p);

            q = TweetNaCl.CryptoScalarmult(n, p);
            Assert.AreEqual(Encoding.UTF7.GetString(q).Length, 32, "wrong size for resulting group element q.");
        }

        [Test]
        public void TestForCryptoScalarmultBase()
        {
            Byte[] n = new Byte[TweetNaCl.SCALARMULT_BYTES];
            Byte[] p = new Byte[TweetNaCl.SCALARMULT_SCALARBYTES];
            Byte[] q = new Byte[TweetNaCl.SCALARMULT_BYTES];

            TweetNaCl.RandomBytes(n);
            TweetNaCl.RandomBytes(p);

            q = TweetNaCl.CryptoScalarmult(n, p);
            Assert.AreEqual(Encoding.UTF7.GetString(q).Length, 32, "wrong size for resulting group element q.");
        }

        [Test]
        public void TestForGenerateEncryptionKeyPair()
        {
            Byte[] pk = new Byte[TweetNaCl.BOX_PUBLICKEYBYTES];
            Byte[] sk = new Byte[TweetNaCl.BOX_SECRETKEYBYTES];

            pk = TweetNaCl.CryptoBoxKeypair(sk);
            Assert.AreEqual(Encoding.UTF7.GetString(pk).Length, 32, "key generation failed.");

            String pk64 = Convert.ToBase64String(pk);
            String sk64 = Convert.ToBase64String(sk);
        }

        [Test]
        public void TestForMessageEncryptionWithCryptoBoxBeforenm()
        {
            Byte[] pk = new Byte[TweetNaCl.BOX_PUBLICKEYBYTES];
            Byte[] sk = new Byte[TweetNaCl.BOX_SECRETKEYBYTES];

            pk = TweetNaCl.CryptoBoxKeypair(sk);
            Assert.AreEqual(Encoding.UTF7.GetString(pk).Length, 32, "key generation failed.");

            String message = "test";
            Byte[] bMessage = Encoding.UTF8.GetBytes(message);
            Byte[] paddedMessage = new Byte[TweetNaCl.BOX_ZEROBYTES + bMessage.Length];
            Byte[] encMessage = new Byte[paddedMessage.Length];
            Byte[] decMessage = new Byte[encMessage.Length];
            Byte[] nonce = new Byte[TweetNaCl.BOX_NONCEBYTES];
            Byte[] k = new Byte[TweetNaCl.BOX_BEFORENMBYTES];


            Array.Copy(bMessage, 0, paddedMessage, TweetNaCl.BOX_ZEROBYTES, bMessage.Length);
            TweetNaCl.RandomBytes(nonce);

            String pubKey = Encoding.ASCII.GetString(pk);
            String secKey = Encoding.ASCII.GetString(sk);

            var result = TweetNaCl.CryptoBoxBeforenm(k, pk, sk);
            Assert.AreNotEqual(result, -1,"generation of K for encryption failed.");
        }

        [Test]
        public void TestForMessageEncryptionWithCryptoBoxAfternm()
        {
            String message = "test";
            Byte[] bMessage = Encoding.UTF8.GetBytes(message);
            Byte[] pk = new Byte[TweetNaCl.BOX_PUBLICKEYBYTES];
            Byte[] sk = new Byte[TweetNaCl.BOX_SECRETKEYBYTES];
            Byte[] paddedMessage = new Byte[TweetNaCl.BOX_ZEROBYTES + bMessage.Length];
            Byte[] encMessage = new Byte[paddedMessage.Length];
            Byte[] decMessage = new Byte[encMessage.Length];
            Byte[] nounce = new Byte[TweetNaCl.BOX_NONCEBYTES];
            Byte[] k = new Byte[TweetNaCl.BOX_BEFORENMBYTES];

            var result = 1;

            Array.Copy(bMessage, 0, paddedMessage, TweetNaCl.BOX_ZEROBYTES, bMessage.Length);

            pk = TweetNaCl.CryptoBoxKeypair(sk);
            Assert.AreEqual(Encoding.UTF7.GetString(pk).Length, 32, "key generation failed.");

            TweetNaCl.RandomBytes(nounce);
            Assert.AreNotEqual(result, -1, "randombytes generation failed.");

            result = TweetNaCl.CryptoBoxBeforenm(k, pk, sk);
            Assert.AreNotEqual(result, -1, "K generation for encryption failed.");

            result = TweetNaCl.CryptoBoxAfternm(encMessage, paddedMessage, nounce, k);
            Assert.AreNotEqual(result, -1, "encryption failed.");
        }

        [Test]
        public void TestForMessageEncryptionWithCryptoBoxOpenAfternm()
        {
            String message = "test";
            Byte[] bMessage = Encoding.UTF8.GetBytes(message);
            Byte[] pk = new Byte[TweetNaCl.BOX_PUBLICKEYBYTES];
            Byte[] sk = new Byte[TweetNaCl.BOX_SECRETKEYBYTES];
            Byte[] paddedMessage = new Byte[TweetNaCl.BOX_ZEROBYTES + bMessage.Length];
            Byte[] encMessage = new Byte[paddedMessage.Length];
            Byte[] decMessage = new Byte[encMessage.Length];
            Byte[] nounce = new Byte[TweetNaCl.BOX_NONCEBYTES];
            Byte[] k = new Byte[TweetNaCl.BOX_BEFORENMBYTES];

            var result = -10;

            Array.Copy(bMessage, 0, paddedMessage, TweetNaCl.BOX_ZEROBYTES, bMessage.Length);

            pk = TweetNaCl.CryptoBoxKeypair(sk);
            Assert.AreEqual(Encoding.UTF7.GetString(pk).Length, 32, "key generation failed.");

            TweetNaCl.RandomBytes(nounce);
            Assert.AreNotEqual(result, -1, "randombytes generation failed.");

            result = TweetNaCl.CryptoBoxBeforenm(k, pk, sk);
            Assert.AreNotEqual(result, -1, "K generation for encryption failed.");

            result = TweetNaCl.CryptoBoxAfternm(encMessage, paddedMessage, nounce, k);
            Assert.AreNotEqual(result, -1, "encryption failed.");

            result = TweetNaCl.CryptoBoxOpenAfternm(decMessage, encMessage, nounce, k);
            Assert.AreNotEqual(result, -1, "decryption failed.");
        }


        [Test]
        public void TestForMessageEncryption()
        {
            String message = "test";
            Byte[] bMessage = Encoding.UTF8.GetBytes(message);
            Byte[] pk = new Byte[TweetNaCl.BOX_PUBLICKEYBYTES];
            Byte[] sk = new Byte[TweetNaCl.BOX_SECRETKEYBYTES];
            Byte[] paddedMessage = new Byte[TweetNaCl.BOX_ZEROBYTES + bMessage.Length];
            Byte[] encMessage = new Byte[paddedMessage.Length];
            Byte[] decMessage = new Byte[encMessage.Length];
            Byte[] nounce = new Byte[TweetNaCl.BOX_NONCEBYTES];
            Byte[] k = new Byte[TweetNaCl.BOX_BEFORENMBYTES];

            var result = -10;

            Array.Copy(bMessage, 0, paddedMessage, TweetNaCl.BOX_ZEROBYTES, bMessage.Length);

            pk = TweetNaCl.CryptoBoxKeypair(sk);
            Assert.AreEqual(Encoding.UTF7.GetString(pk).Length, 32, "key generation failed.");

            TweetNaCl.RandomBytes(nounce);
            Assert.AreNotEqual(result, -1, "randombytes generation failed.");

            TweetNaCl.CryptoBox(encMessage, paddedMessage, nounce, pk, sk);
            Assert.AreNotEqual(result, -1, "encryption failed.");
        }

        [Test]
        public void TestForMessageDecryptionDifferentKeyPair()
        {
            Byte[] apk = new Byte[TweetNaCl.BOX_PUBLICKEYBYTES];
            Byte[] ask = new Byte[TweetNaCl.BOX_SECRETKEYBYTES];

            Byte[] bpk = new Byte[TweetNaCl.BOX_PUBLICKEYBYTES];
            Byte[] bsk = new Byte[TweetNaCl.BOX_SECRETKEYBYTES];

            String message = "test";
            Byte[] bMessage = Encoding.UTF8.GetBytes(message);
            Byte[] paddedMessage = new Byte[TweetNaCl.BOX_ZEROBYTES + bMessage.Length];
            Byte[] encMessage = new Byte[paddedMessage.Length];
            Byte[] decMessage = new Byte[encMessage.Length];
            Byte[] nounce = new Byte[TweetNaCl.BOX_NONCEBYTES];
            Byte[] k = new Byte[TweetNaCl.BOX_BEFORENMBYTES];

            var result = -10;

            Array.Copy(bMessage, 0, paddedMessage, TweetNaCl.BOX_ZEROBYTES, bMessage.Length);
            
            apk = TweetNaCl.CryptoBoxKeypair(ask);
            Assert.AreEqual(Encoding.UTF7.GetString(apk).Length, 32, "key generation failed.");

            bpk = TweetNaCl.CryptoBoxKeypair(bsk);
            Assert.AreEqual(Encoding.UTF7.GetString(bpk).Length, 32, "key generation failed.");

            TweetNaCl.RandomBytes(nounce);
            Assert.AreNotEqual(result, -1, "randombytes generation failed.");

            TweetNaCl.CryptoBox(encMessage, paddedMessage, nounce, bpk, ask);
            Assert.AreNotEqual(result, -1, "encryption failed.");

            TweetNaCl.CryptoBoxOpen(decMessage, encMessage, nounce, apk, bsk);
            Assert.AreNotEqual(result, -1, "decryption failed.");
        }

        [Test]
        public void TestForMessageDecryptionSecretBox()
        {
            Byte[] bsk = new Byte[TweetNaCl.SECRETBOX_NONCEBYTES];

            String message = "test";
            Byte[] bMessage = Encoding.UTF8.GetBytes(message);
            Byte[] sk = new Byte[TweetNaCl.SECRETBOX_KEYBYTES];
            Byte[] paddedMessage = new Byte[TweetNaCl.BOX_ZEROBYTES + bMessage.Length];
            Byte[] encMessage = new Byte[paddedMessage.Length];
            Byte[] decMessage = new Byte[encMessage.Length];
            Byte[] nounce = new Byte[TweetNaCl.BOX_NONCEBYTES];

            Array.Copy(bMessage, 0, paddedMessage, TweetNaCl.BOX_ZEROBYTES, bMessage.Length);

            TweetNaCl.RandomBytes(sk);
            TweetNaCl.RandomBytes(nounce);

            var result = TweetNaCl.CryptoSecretBox(encMessage, paddedMessage, nounce, sk);
            Assert.AreNotEqual(result, -1, "encryption failed.");

            result = TweetNaCl.CryptoSecretBoxOpen(decMessage, encMessage, nounce, sk);
            Assert.AreNotEqual(result, -1, "decryption failed.");
        }

        [Test]
        public void TestForMessageHashing()
        {
            String message = "test";
            Byte[] bMessage = Encoding.UTF8.GetBytes(message);
            Byte[] hsh1 = new Byte[TweetNaCl.HASH_BYTES];
            Byte[] hsh2 = new Byte[TweetNaCl.HASH_BYTES];

            var result = -10;

            TweetNaCl.CryptoHash(hsh1, bMessage, bMessage.Length);
            Assert.AreNotEqual(result, -1, "First hashing call for message generation failed.");

            TweetNaCl.CryptoHash(hsh2, bMessage, bMessage.Length);
            Assert.AreNotEqual(result, -1, "Second hashing call for message generation failed.");


            Assert.AreEqual(hsh1, hsh2, "hash for message are not equal.");
        }

        [Test]
        public void TestForMessageSignKeypair()
        {
            Byte[] spk = new Byte[TweetNaCl.SIGN_PUBLICKEYBYTES];
            Byte[] ssk = new Byte[TweetNaCl.SIGN_SECRETKEYBYTES];
                        
            var result = TweetNaCl.CryptoSignKeypair(spk,ssk);
            Assert.AreNotEqual(result, -1, "Message sign keyparis generation failed.");
        }

        [Test]
        public void TestForMessageSign()
        {
            String message = "test";
            Byte[] bMessage = Encoding.UTF8.GetBytes(message);
            Byte[] spk = new Byte[TweetNaCl.SIGN_PUBLICKEYBYTES];
            Byte[] ssk = new Byte[TweetNaCl.SIGN_SECRETKEYBYTES];
            Byte[] sMessage = new Byte[TweetNaCl.SIGN_BYTES + bMessage.Length];

            var result = TweetNaCl.CryptoSignKeypair(spk, ssk);
            Assert.AreNotEqual(result, -1, "Message sign keyparis generation failed.");

            result = TweetNaCl.CryptoSign(sMessage, bMessage, ssk);
            Assert.AreNotEqual(result, -1, "Message sign failed.");
        }

        [Test]
        public void TestForMessageSignOpen()
        {
            String message = "test";
            Byte[] bMessage = Encoding.UTF8.GetBytes(message);
            Byte[] spk = new Byte[TweetNaCl.SIGN_PUBLICKEYBYTES];
            Byte[] ssk = new Byte[TweetNaCl.SIGN_SECRETKEYBYTES];
            Byte[] sMessage = new Byte[TweetNaCl.SIGN_BYTES + bMessage.Length];
            Byte[] cMessage = new Byte[bMessage.Length];

            var result = TweetNaCl.CryptoSignKeypair(spk, ssk);
            Assert.AreNotEqual(result, -1, "Message sign keyparis generation failed.");

            result = TweetNaCl.CryptoSign(sMessage, bMessage, ssk);
            Assert.AreNotEqual(result, -1, "Message sign failed.");

            result = TweetNaCl.CryptoSignOpen(cMessage, sMessage, spk);
            Assert.AreNotEqual(result, -1, "Message sign verification failed.");

            Assert.AreEqual(Encoding.UTF8.GetString(cMessage), message, "Messages sign verification failed.");
        }
    }
}
