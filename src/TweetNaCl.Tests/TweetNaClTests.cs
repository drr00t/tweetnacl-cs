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

            String text10 =  Encoding.UTF8.GetString(b10);
            String text100 = Encoding.UTF8.GetString(b100);
            String text200 = Encoding.UTF8.GetString(b200);
            String text1 = Encoding.UTF8.GetString(b1);
        }

        [Test]
        public void TestForGenerateEncryptionKeyPair()
        {
            Byte[] pk = new Byte[TweetNaCl.BOX_PUBLIC_KEY_BYTES];
            Byte[] sk = new Byte[TweetNaCl.BOX_SECRET_KEY_BYTES];

            TweetNaCl.CryptoBoxKeypair(pk,sk);

            String pubKey = Encoding.UTF8.GetString(pk);
            String secKey = Encoding.UTF8.GetString(sk);

            Assert.AreEqual(pubKey.Count(), TweetNaCl.BOX_PUBLIC_KEY_BYTES);
            Assert.AreEqual(pubKey.Count(), TweetNaCl.BOX_SECRET_KEY_BYTES);

        }

        [Test]
        public void TestForMessageEncryptionWithCryptoBoxBeforenm()
        {
            Byte[] pk = new Byte[TweetNaCl.BOX_PUBLIC_KEY_BYTES];
            Byte[] sk = new Byte[TweetNaCl.BOX_SECRET_KEY_BYTES];

            TweetNaCl.CryptoBoxKeypair(pk, sk);

            String message = "test";
            Byte[] bMessage = Encoding.UTF8.GetBytes(message);
            Byte[] paddedMessage = new Byte[32 + bMessage.Length];
            Byte[] encMessage = new Byte[32 + bMessage.Length];
            Byte[] nonce = new Byte[24];
            Byte[] k = new Byte[32];


            Array.Copy(bMessage, 0, paddedMessage, 32, bMessage.Length);
            TweetNaCl.RandomBytes(nonce);

            String pubKey = Encoding.UTF8.GetString(pk);
            String secKey = Encoding.UTF8.GetString(sk);

            var result = TweetNaCl.CryptoBoxBeforenm(k, pk, sk);
            Assert.AreNotEqual(result, -1,"generation of K for encryption failed.");
        }

        [Test]
        public void TestForMessageEncryptionWithCryptoBoxAfternm()
        {
            String message = "test";
            Byte[] bMessage = Encoding.UTF8.GetBytes(message);
            Byte[] pk = new Byte[TweetNaCl.BOX_PUBLIC_KEY_BYTES];
            Byte[] sk = new Byte[TweetNaCl.BOX_SECRET_KEY_BYTES];
            Byte[] paddedMessage = new Byte[32 + bMessage.Length];
            Byte[] encMessage = new Byte[32 + bMessage.Length];
            Byte[] decMessage = new Byte[16 + bMessage.Length];
            Byte[] nonce = new Byte[24];
            Byte[] k = new Byte[32];

            var result = -10;

            Array.Copy(bMessage, 0, paddedMessage, 32, bMessage.Length);

            TweetNaCl.CryptoBoxKeypair(pk, sk);
            Assert.AreNotEqual(result, -1, "key pair generation failed.");

            TweetNaCl.RandomBytes(nonce);
            Assert.AreNotEqual(result, -1, "randombytes generation failed.");

            result = TweetNaCl.CryptoBoxBeforenm(k, pk, sk);
            Assert.AreNotEqual(result, -1, "K generation for encryption failed.");

            result = TweetNaCl.CryptoBoxAfternm(encMessage, paddedMessage, paddedMessage.Length, nonce, k);
            Assert.AreNotEqual(result, -1, "encryption failed.");
        }

        [Test]
        public void TestForMessageEncryptionWithCryptoBoxOpenAfternm()
        {
            String message = "test";
            Byte[] bMessage = Encoding.UTF8.GetBytes(message);
            Byte[] pk = new Byte[TweetNaCl.BOX_PUBLIC_KEY_BYTES];
            Byte[] sk = new Byte[TweetNaCl.BOX_SECRET_KEY_BYTES];
            Byte[] paddedMessage = new Byte[32 + bMessage.Length];
            Byte[] encMessage = new Byte[32 + bMessage.Length];
            Byte[] decMessage = new Byte[16 + bMessage.Length];
            Byte[] nonce = new Byte[24];
            Byte[] k = new Byte[32];

            var result = -10;

            Array.Copy(bMessage, 0, paddedMessage, 32, bMessage.Length);

            TweetNaCl.CryptoBoxKeypair(pk, sk);
            Assert.AreNotEqual(result, -1, "key pair generation failed.");

            TweetNaCl.RandomBytes(nonce);
            Assert.AreNotEqual(result, -1, "randombytes generation failed.");

            result = TweetNaCl.CryptoBoxBeforenm(k, pk, sk);
            Assert.AreNotEqual(result, -1, "K generation for encryption failed.");

            result = TweetNaCl.CryptoBoxAfternm(encMessage, paddedMessage, paddedMessage.Length, nonce, k);
            Assert.AreNotEqual(result, -1, "encryption failed.");

            result = TweetNaCl.CryptoBoxOpenAfternm(decMessage, encMessage, paddedMessage.Length, nonce, k);
            Assert.AreNotEqual(result, -1, "decryption failed.");
        }


        [Test]
        public void TestForMessageEncryption()
        {
            String message = "test";
            Byte[] bMessage = Encoding.UTF8.GetBytes(message);
            Byte[] pk = new Byte[TweetNaCl.BOX_PUBLIC_KEY_BYTES];
            Byte[] sk = new Byte[TweetNaCl.BOX_SECRET_KEY_BYTES];
            Byte[] paddedMessage = new Byte[32 + bMessage.Length];
            Byte[] encMessage = new Byte[32 + bMessage.Length];
            Byte[] decMessage = new Byte[16 + bMessage.Length];
            Byte[] nonce = new Byte[24];
            Byte[] k = new Byte[32];

            var result = -10;

            Array.Copy(bMessage, 0, paddedMessage, 32, bMessage.Length);

            TweetNaCl.CryptoBoxKeypair(pk, sk);
            Assert.AreNotEqual(result, -1, "key pair generation failed.");

            TweetNaCl.RandomBytes(nonce);
            Assert.AreNotEqual(result, -1, "randombytes generation failed.");

            TweetNaCl.CryptoBox(encMessage, paddedMessage, paddedMessage.Count(), nonce, pk, sk);
            Assert.AreNotEqual(result, -1, "encryption failed.");
        }

        [Test]
        public void TestForMessageDecryptionDifferentKeyPair()
        {
            Byte[] apk = new Byte[TweetNaCl.BOX_PUBLIC_KEY_BYTES];
            Byte[] ask = new Byte[TweetNaCl.BOX_SECRET_KEY_BYTES];

            Byte[] bpk = new Byte[TweetNaCl.BOX_PUBLIC_KEY_BYTES];
            Byte[] bsk = new Byte[TweetNaCl.BOX_SECRET_KEY_BYTES];

            String message = "test";
            Byte[] bMessage = Encoding.UTF8.GetBytes(message);
            Byte[] pk = new Byte[TweetNaCl.BOX_PUBLIC_KEY_BYTES];
            Byte[] sk = new Byte[TweetNaCl.BOX_SECRET_KEY_BYTES];
            Byte[] paddedMessage = new Byte[32 + bMessage.Length];
            Byte[] encMessage = new Byte[32 + bMessage.Length];
            Byte[] decMessage = new Byte[16 + bMessage.Length];
            Byte[] nonce = new Byte[24];
            Byte[] k = new Byte[32];

            var result = -10;

            Array.Copy(bMessage, 0, paddedMessage, 32, bMessage.Length);

            TweetNaCl.CryptoBoxKeypair(apk, ask);
            Assert.AreNotEqual(result, -1, "key pair A generation failed.");

            TweetNaCl.CryptoBoxKeypair(bpk, bsk);
            Assert.AreNotEqual(result, -1, "key pair B generation failed.");

            TweetNaCl.RandomBytes(nonce);
            Assert.AreNotEqual(result, -1, "randombytes generation failed.");

            TweetNaCl.CryptoBox(encMessage, paddedMessage, paddedMessage.Count(), nonce, bpk, ask);
            Assert.AreNotEqual(result, -1, "encryption failed.");

            TweetNaCl.CryptoBoxOpen(decMessage, encMessage, encMessage.Count(), nonce, apk, bsk);
            Assert.AreNotEqual(result, -1, "decryption failed.");
        }
    }
}
