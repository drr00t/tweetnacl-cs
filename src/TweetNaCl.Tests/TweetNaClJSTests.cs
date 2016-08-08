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
    public class TweetNaClJSTests
    {

        [Test]
        public void TestForMessageDecryptionTweetNaCljsKeyPair()
        {
            Byte[] apk = Convert.FromBase64String("GK4GzNY+fbkRPd5fwYUaca70iENh2A1QRss1KBtpWU4=");
            Byte[] ask = Convert.FromBase64String("HQT4qtjv/3Q0nGYX4DB776e6QeUE40wr71MxNSg0+bc=");

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
            Assert.AreNotEqual(result, -1, "key pair A generation failed.");

            bpk = TweetNaCl.CryptoBoxKeypair(bsk);
            Assert.AreNotEqual(result, -1, "key pair B generation failed.");

            TweetNaCl.RandomBytes(nounce);
            Assert.AreNotEqual(result, -1, "randombytes generation failed.");

            TweetNaCl.CryptoBox(encMessage, paddedMessage, nounce, bpk, ask);
            Assert.AreNotEqual(result, -1, "encryption failed.");

            TweetNaCl.CryptoBoxOpen(decMessage, encMessage, nounce, apk, bsk);
            Assert.AreNotEqual(result, -1, "decryption failed.");
        }
    }
}
