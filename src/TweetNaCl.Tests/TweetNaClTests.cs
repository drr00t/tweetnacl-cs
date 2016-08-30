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
            Byte[] n = new Byte[TweetNaCl.ScalarmultBytes];
            Byte[] p = new Byte[TweetNaCl.ScalarBytes];
            Byte[] q = new Byte[TweetNaCl.ScalarmultBytes];

            TweetNaCl.RandomBytes(n);
            TweetNaCl.RandomBytes(p);

            q = TweetNaCl.CryptoScalarmult(n, p);
            Assert.AreEqual(Encoding.ASCII.GetString(q).Length, 32, "wrong size for resulting group element q.");
        }

        [Test]
        public void TestForCryptoScalarmultBase()
        {
            Byte[] n = new Byte[TweetNaCl.ScalarmultBytes];
            Byte[] p = new Byte[TweetNaCl.ScalarBytes];
            Byte[] q = new Byte[TweetNaCl.ScalarmultBytes];

            TweetNaCl.RandomBytes(n);
            TweetNaCl.RandomBytes(p);

            q = TweetNaCl.CryptoScalarmult(n, p);
            Assert.AreEqual(Encoding.ASCII.GetString(q).Length, 32, "wrong size for resulting group element q.");
        }

        [Test]
        public void TestForGenerateEncryptionKeyPair()
        {
            Byte[] pk = new Byte[TweetNaCl.BoxPublicKeyBytes];
            Byte[] sk = new Byte[TweetNaCl.BoxSecretKeyBytes];

            pk = TweetNaCl.CryptoBoxKeypair(sk);
            Assert.AreEqual(Encoding.ASCII.GetString(pk).Length, 32, "key generation failed.");

            String pk64 = Convert.ToBase64String(pk);
            String sk64 = Convert.ToBase64String(sk);
        }

        [Test]
        public void TestForMessageEncryptionWithCryptoBoxBeforenm()
        {
            Byte[] pk = new Byte[TweetNaCl.BoxPublicKeyBytes];
            Byte[] sk = new Byte[TweetNaCl.BoxSecretKeyBytes];

            pk = TweetNaCl.CryptoBoxKeypair(sk);
            Assert.AreEqual(Encoding.ASCII.GetString(pk).Length, 32, "key generation failed.");

            String message = "test";
            Byte[] bMessage = Encoding.UTF8.GetBytes(message);
            Byte[] paddedMessage = new Byte[TweetNaCl.BoxZeroBytes + bMessage.Length];
            Byte[] encMessage = new Byte[paddedMessage.Length];
            Byte[] decMessage = new Byte[encMessage.Length];
            Byte[] nonce = new Byte[TweetNaCl.BoxNonceBytes];

            TweetNaCl.RandomBytes(nonce);

            String pubKey = Encoding.ASCII.GetString(pk);
            String secKey = Encoding.ASCII.GetString(sk);

            var k = TweetNaCl.CryptoBoxBeforenm( pk, sk);
            Assert.AreEqual(k.Length, TweetNaCl.BoxBeforenmBytes,"generation of K for encryption failed.");
        }

        [Test]
        public void TestForMessageEncryptionWithCryptoBoxAfternm()
        {
            String message = "test";
            Byte[] bMessage = Encoding.UTF8.GetBytes(message);
            Byte[] pk = new Byte[TweetNaCl.BoxPublicKeyBytes];
            Byte[] sk = new Byte[TweetNaCl.BoxSecretKeyBytes];
            Byte[] nonce = new Byte[TweetNaCl.BoxNonceBytes];

            var result = 1;

            pk = TweetNaCl.CryptoBoxKeypair(sk);
            Assert.AreEqual(Encoding.ASCII.GetString(pk).Length, 32, "key generation failed.");

            TweetNaCl.RandomBytes(nonce);
            Assert.AreNotEqual(result, -1, "randombytes generation failed.");

            var k = TweetNaCl.CryptoBoxBeforenm(pk, sk);

            var encMessage = TweetNaCl.CryptoBoxAfternm(bMessage, nonce, k);
            Assert.AreEqual(encMessage.Length, bMessage.Length + TweetNaCl.BoxBoxZeroBytes, "encryption failed.");
        }

        [Test]
        public void TestForMessageEncryptionWithCryptoBoxOpenAfternm()
        {
            String message = "test";
            Byte[] bMessage = Encoding.UTF8.GetBytes(message);
            Byte[] pk = new Byte[TweetNaCl.BoxPublicKeyBytes];
            Byte[] sk = new Byte[TweetNaCl.BoxSecretKeyBytes];
            Byte[] nonce = new Byte[TweetNaCl.BoxNonceBytes];

            pk = TweetNaCl.CryptoBoxKeypair(sk);

            TweetNaCl.RandomBytes(nonce);

            var k = TweetNaCl.CryptoBoxBeforenm(pk, sk);
            Assert.AreEqual(k.Length, TweetNaCl.BoxBeforenmBytes, "K generation for encryption failed.");

            var encMessage = TweetNaCl.CryptoBoxAfternm(bMessage, nonce, k);
            Assert.AreEqual(encMessage.Length, bMessage.Length + TweetNaCl.BoxBoxZeroBytes, "encryption failed.");

            var decMessage = TweetNaCl.CryptoBoxOpenAfternm(encMessage, nonce, k);
            Assert.AreEqual(decMessage.Length, bMessage.Length, "decryption failed.");
            Assert.AreEqual(decMessage, bMessage, "decryption failed.");
        }


        [Test]
        public void TestForMessageEncryption()
        {
            String message = "test";
            Byte[] bMessage = Encoding.UTF8.GetBytes(message);
            Byte[] pk = new Byte[TweetNaCl.BoxPublicKeyBytes];
            Byte[] sk = new Byte[TweetNaCl.BoxSecretKeyBytes];
            Byte[] nonce = new Byte[TweetNaCl.BoxNonceBytes];
            Byte[] k = new Byte[TweetNaCl.BoxBeforenmBytes];

            pk = TweetNaCl.CryptoBoxKeypair(sk);
            TweetNaCl.RandomBytes(nonce);

            var encMessage = TweetNaCl.CryptoBox(bMessage, nonce, pk, sk);
            Assert.AreEqual(encMessage.Length, bMessage.Length + TweetNaCl.BoxBoxZeroBytes, "encryption failed.");
        }

        [Test]
        public void TestForMessageDecryptionDifferentKeyPair()
        {
            Byte[] apk = new Byte[TweetNaCl.BoxPublicKeyBytes];
            Byte[] ask = new Byte[TweetNaCl.BoxSecretKeyBytes];

            Byte[] bpk = new Byte[TweetNaCl.BoxPublicKeyBytes];
            Byte[] bsk = new Byte[TweetNaCl.BoxSecretKeyBytes];

            String message = "test";
            Byte[] bMessage = Encoding.UTF8.GetBytes(message);
            Byte[] nonce = new Byte[TweetNaCl.BoxNonceBytes];
            Byte[] k = new Byte[TweetNaCl.BoxBeforenmBytes];

            apk = TweetNaCl.CryptoBoxKeypair(ask);
            bpk = TweetNaCl.CryptoBoxKeypair(bsk);

            TweetNaCl.RandomBytes(nonce);

            var encMessage = TweetNaCl.CryptoBox(bMessage, nonce, bpk, ask);
            Assert.AreEqual(encMessage.Length, bMessage.Length + TweetNaCl.BoxBoxZeroBytes, "encryption failed.");


            var decMessage = TweetNaCl.CryptoBoxOpen(encMessage, nonce, apk, bsk);
            Assert.AreEqual(decMessage.Length, bMessage.Length, "encryption failed.");
        }

        [Test]
        public void TestForMessageDecryptionSecretBox()
        {
            Byte[] bsk = new Byte[TweetNaCl.SecretBoxNonceBytes];

            String message = "test";
            Byte[] bMessage = Encoding.UTF8.GetBytes(message);
            Byte[] sk = new Byte[TweetNaCl.SecretBoxKeyBytes];
            Byte[] nonce = new Byte[TweetNaCl.SecretBoxNonceBytes];

            TweetNaCl.RandomBytes(sk);
            TweetNaCl.RandomBytes(nonce);

            var encMessage = TweetNaCl.CryptoSecretBox(bMessage, nonce, sk);
            Assert.AreEqual(encMessage.Length, bMessage.Length + TweetNaCl.BoxBoxZeroBytes, "encryption failed.");

            var decMessage = TweetNaCl.CryptoSecretBoxOpen(encMessage, nonce, sk);
            Assert.AreEqual(decMessage.Length, bMessage.Length, "decryption failed.");
            Assert.AreEqual(decMessage, bMessage, "decryption failed.");
        }

        [Test]
        public void TestForMessageHashing()
        {
            String message = "test";
            Byte[] bMessage = Encoding.UTF8.GetBytes(message);
            Byte[] hsh1 = new Byte[TweetNaCl.HashBytes];
            Byte[] hsh2 = new Byte[TweetNaCl.HashBytes];

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
            
            Byte[] ssk = new Byte[TweetNaCl.SignSecretKeyBytes];

            Byte[] spk = TweetNaCl.CryptoSignKeypair(ssk);
            Assert.AreEqual(Encoding.ASCII.GetString(spk).Length, 32, "Public Key for message sign generation failed.");
            Assert.AreEqual(Encoding.ASCII.GetString(ssk).Length, 64, "Secret Key for message sign generation failed.");
        }

        [Test]
        public void TestForMessageSign()
        {
            String message = "test";
            Byte[] bMessage = Encoding.UTF8.GetBytes(message);
            Byte[] ssk = new Byte[TweetNaCl.SignSecretKeyBytes];
            Byte[] sMessage;

            var spk = TweetNaCl.CryptoSignKeypair(ssk);

            sMessage = TweetNaCl.CryptoSign(bMessage, ssk);
            Assert.AreEqual(Encoding.ASCII.GetString(sMessage).Length, bMessage.Length + TweetNaCl.SignBytes, "Message sign failed.");
        }

        [Test]
        public void TestForMessageSignOpen()
        {
            String message = "test";
            Byte[] bMessage = Encoding.UTF8.GetBytes(message);
            Byte[] ssk = new Byte[TweetNaCl.SignSecretKeyBytes];
            Byte[] sMessage = new Byte[TweetNaCl.SignBytes + bMessage.Length];
            Byte[] cMessage = new Byte[bMessage.Length];

            var spk = TweetNaCl.CryptoSignKeypair(ssk);
            sMessage = TweetNaCl.CryptoSign(bMessage, ssk);
            Assert.AreEqual(sMessage.Length, bMessage.Length + TweetNaCl.SignBytes, "Message sign failed.");

            cMessage = TweetNaCl.CryptoSignOpen(sMessage, spk);
            Assert.AreEqual(cMessage.Length, bMessage.Length, "Message sign verification failed.");
            Assert.AreEqual(Encoding.UTF8.GetString(cMessage), message, "Messages sign verification failed.");
        }
    }
}
