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




using NaCl;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace TweetNaCl.Tests
{
    public class TweetNaClTests
    {

        public void RandomBytesGeneration_Should_Maintain_Length()
        {
            //Arrange
            Byte[] b1 = new Byte[1];
            Byte[] b10 = new Byte[10];
            Byte[] b100 = new Byte[100];
            Byte[] b200 = new Byte[200];

            //Act
            TweetNaCl.RandomBytes(b1);
            TweetNaCl.RandomBytes(b10);
            TweetNaCl.RandomBytes(b100);
            TweetNaCl.RandomBytes(b200);

            //Assert
            String text1 = Encoding.ASCII.GetString(b1);
            String text10 = Encoding.ASCII.GetString(b10);
            String text100 = Encoding.ASCII.GetString(b100);
            String text200 = Encoding.ASCII.GetString(b200);

            Assert.Equal(1, text1.Length);
            Assert.Equal(10, text10.Length);
            Assert.Equal(100, text100.Length);
            Assert.Equal(200, text200.Length);
        }

        [Fact]
        public void CryptoScalarmult_Should_Success()
        {
            //Arrange
            Byte[] n = new Byte[TweetNaCl.ScalarmultBytes];
            Byte[] p = new Byte[TweetNaCl.ScalarBytes];
            Byte[] q = new Byte[TweetNaCl.ScalarmultBytes];

            TweetNaCl.RandomBytes(n);
            TweetNaCl.RandomBytes(p);

            //Act
            q = TweetNaCl.CryptoScalarmult(n, p);

            //Assert
            Assert.Equal(Encoding.ASCII.GetString(q).Length, 32);
        }

        [Fact]
        public void CryptoBoxKeypair_Should_Success()
        {
            //Arrange
            Byte[] pk = new Byte[TweetNaCl.BoxPublicKeyBytes];
            Byte[] sk = new Byte[TweetNaCl.BoxSecretKeyBytes];

            //Act
            pk = TweetNaCl.CryptoBoxKeypair(sk);

            //Assert
            Assert.Equal(Encoding.ASCII.GetString(pk).Length, 32);
        }

        [Fact]
        public void CryptoBoxBeforenm_MessageEncryption_Should_Success()
        {
            //Arrange
            Byte[] pk = new Byte[TweetNaCl.BoxPublicKeyBytes];
            Byte[] sk = new Byte[TweetNaCl.BoxSecretKeyBytes];

            pk = TweetNaCl.CryptoBoxKeypair(sk);

            //Act
            var k = TweetNaCl.CryptoBoxBeforenm(pk, sk);

            //Assert
            Assert.Equal(k.Length, TweetNaCl.BoxBeforenmBytes);
        }

        [Fact]
        public void CryptoBoxAfternm_MessageEncryption_Should_Success()
        {
            //Arrange
            String message = "test";
            Byte[] bMessage = Encoding.UTF8.GetBytes(message);
            Byte[] pk = new Byte[TweetNaCl.BoxPublicKeyBytes];
            Byte[] sk = new Byte[TweetNaCl.BoxSecretKeyBytes];
            Byte[] nonce = new Byte[TweetNaCl.BoxNonceBytes];
            TweetNaCl.RandomBytes(nonce);

            pk = TweetNaCl.CryptoBoxKeypair(sk);

            var k = TweetNaCl.CryptoBoxBeforenm(pk, sk);

            //Act
            var encMessage = TweetNaCl.CryptoBoxAfternm(bMessage, nonce, k);

            //Assert
            Assert.Equal(encMessage.Length, bMessage.Length + TweetNaCl.BoxBoxZeroBytes);
        }
        [Fact]

        public void CryptoBoxOpenAfternm_Decryption_Should_Success()
        {
            //Arrange
            String expectedMessage = "test";
            Byte[] bMessage = Encoding.UTF8.GetBytes(expectedMessage);
            Byte[] pk = new Byte[TweetNaCl.BoxPublicKeyBytes];
            Byte[] sk = new Byte[TweetNaCl.BoxSecretKeyBytes];
            Byte[] nonce = new Byte[TweetNaCl.BoxNonceBytes];

            pk = TweetNaCl.CryptoBoxKeypair(sk);
            TweetNaCl.RandomBytes(nonce);
            var k = TweetNaCl.CryptoBoxBeforenm(pk, sk);

            //Act
            var encMessage = TweetNaCl.CryptoBoxAfternm(bMessage, nonce, k);
            var decMessage = TweetNaCl.CryptoBoxOpenAfternm(encMessage, nonce, k);

            //Assert
            Assert.Equal(decMessage.Length, bMessage.Length);
            Assert.Equal(decMessage, bMessage);

            var resultMessage = Encoding.ASCII.GetString(decMessage);
            Assert.Equal(resultMessage, expectedMessage);
        }


        [Fact]
        public void CryptoBox_MessageEncryption_Should_Success()
        {
            //Arrange
            String message = "test";
            Byte[] bMessage = Encoding.UTF8.GetBytes(message);
            Byte[] pk = new Byte[TweetNaCl.BoxPublicKeyBytes];
            Byte[] sk = new Byte[TweetNaCl.BoxSecretKeyBytes];
            Byte[] nonce = new Byte[TweetNaCl.BoxNonceBytes];

            pk = TweetNaCl.CryptoBoxKeypair(sk);
            TweetNaCl.RandomBytes(nonce);

            //Act
            var encMessage = TweetNaCl.CryptoBox(bMessage, nonce, pk, sk);

            //Assert
            Assert.Equal(encMessage.Length, bMessage.Length + TweetNaCl.BoxBoxZeroBytes);
        }

        [Fact]
        public void CryptoBoxOpen_DecryptionDifferentKeyPair_Should_Success()
        {
            //Arrange
            Byte[] apk = new Byte[TweetNaCl.BoxPublicKeyBytes];
            Byte[] ask = new Byte[TweetNaCl.BoxSecretKeyBytes];

            Byte[] bpk = new Byte[TweetNaCl.BoxPublicKeyBytes];
            Byte[] bsk = new Byte[TweetNaCl.BoxSecretKeyBytes];

            String expectedMessage = "test";
            Byte[] bMessage = Encoding.UTF8.GetBytes(expectedMessage);
            Byte[] nonce = new Byte[TweetNaCl.BoxNonceBytes];

            apk = TweetNaCl.CryptoBoxKeypair(ask);
            bpk = TweetNaCl.CryptoBoxKeypair(bsk);

            TweetNaCl.RandomBytes(nonce);

            //Act
            var encMessage = TweetNaCl.CryptoBox(bMessage, nonce, bpk, ask);
            var decMessage = TweetNaCl.CryptoBoxOpen(encMessage, nonce, apk, bsk);

            //Assert
            Assert.Equal(encMessage.Length, bMessage.Length + TweetNaCl.BoxBoxZeroBytes);
            Assert.Equal(decMessage.Length, bMessage.Length);

            var resultMessage = Encoding.ASCII.GetString(decMessage);
            Assert.Equal(resultMessage, expectedMessage);
        }

        [Fact]
        public void CryptoSecretBox_Should_Success()
        {
            //Arrange
            String message = "test";
            Byte[] bMessage = Encoding.UTF8.GetBytes(message);
            Byte[] sk = new Byte[TweetNaCl.SecretBoxKeyBytes];
            Byte[] nonce = new Byte[TweetNaCl.SecretBoxNonceBytes];
            TweetNaCl.RandomBytes(sk);
            TweetNaCl.RandomBytes(nonce);

            //Act
            var encMessage = TweetNaCl.CryptoSecretBox(bMessage, nonce, sk);

            //Assert
            Assert.Equal(encMessage.Length, bMessage.Length + TweetNaCl.BoxBoxZeroBytes);
        }

        [Fact]
        public void CryptoSecretBoxOpen_Decryption_Should_Success()
        {
            //Arrange
            String message = "test";
            Byte[] bMessage = Encoding.UTF8.GetBytes(message);
            Byte[] sk = new Byte[TweetNaCl.SecretBoxKeyBytes];
            Byte[] nonce = new Byte[TweetNaCl.SecretBoxNonceBytes];

            TweetNaCl.RandomBytes(sk);
            TweetNaCl.RandomBytes(nonce);

            var encMessage = TweetNaCl.CryptoSecretBox(bMessage, nonce, sk);

            //Act
            var decMessage = TweetNaCl.CryptoSecretBoxOpen(encMessage, nonce, sk);
            Assert.Equal(decMessage.Length, bMessage.Length);
            Assert.Equal(decMessage, bMessage);
        }

        [Fact]
        public void CryptoHash_MessageHashing_Should_Success()
        {
            //Arrange
            String message = "test";
            Byte[] bMessage = Encoding.UTF8.GetBytes(message);
            Byte[] hsh1 = new Byte[TweetNaCl.HashBytes];
            Byte[] hsh2 = new Byte[TweetNaCl.HashBytes];

            var firstResult = 0;
            var secontResult = 0;

            //Act
            firstResult = TweetNaCl.CryptoHash(hsh1, bMessage, bMessage.Length);
            secontResult = TweetNaCl.CryptoHash(hsh2, bMessage, bMessage.Length);

            //Assert
            Assert.NotEqual(firstResult, -1);
            Assert.NotEqual(secontResult, -1);
            Assert.Equal(hsh1, hsh2);
        }

        [Fact]
        public void CryptoSignKeypair_Generation_Should_Success()
        {
            //Arrange
            Byte[] ssk = new Byte[TweetNaCl.SignSecretKeyBytes];

            //Act
            Byte[] spk = TweetNaCl.CryptoSignKeypair(ssk);

            //Assert
            Assert.Equal(Encoding.ASCII.GetString(spk).Length, 32);
            Assert.Equal(Encoding.ASCII.GetString(ssk).Length, 64);
        }

        [Fact]
        public void CryptoSign_Should_Success()
        {
            //Arrange
            String message = "test";
            Byte[] bMessage = Encoding.UTF8.GetBytes(message);
            Byte[] ssk = new Byte[TweetNaCl.SignSecretKeyBytes];
            Byte[] sMessage;

            //Act
            var spk = TweetNaCl.CryptoSignKeypair(ssk);
            sMessage = TweetNaCl.CryptoSign(bMessage, ssk);

            //Assert
            Assert.Equal(Encoding.ASCII.GetString(sMessage).Length, bMessage.Length + TweetNaCl.SignBytes);
        }

        [Fact]
        public void CryptoSignOpen_Should_Success()
        {
            //Arrange
            String message = "test";
            Byte[] bMessage = Encoding.UTF8.GetBytes(message);
            Byte[] ssk = new Byte[TweetNaCl.SignSecretKeyBytes];
            Byte[] sMessage = new Byte[TweetNaCl.SignBytes + bMessage.Length];
            Byte[] cMessage = new Byte[bMessage.Length];

            var spk = TweetNaCl.CryptoSignKeypair(ssk);
            sMessage = TweetNaCl.CryptoSign(bMessage, ssk);

            //Act
            cMessage = TweetNaCl.CryptoSignOpen(sMessage, spk);
            Assert.Equal(cMessage.Length, bMessage.Length);
            Assert.Equal(Encoding.UTF8.GetString(cMessage), message);
        }
    }
}
