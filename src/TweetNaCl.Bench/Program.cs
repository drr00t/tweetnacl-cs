using Metrics;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TweetNaCl.Bench
{
    class Program
    {
        

        static void Main(string[] args)
        {
            Timer timer = Metric.Timer("Requests", Unit.Requests);

            for (var i = 0; i < 10; i++)
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

                using (var context = timer.NewContext("Encryption"))
                {
                    var encMessage = TweetNaCl.CryptoBox(bMessage, nonce, bpk, ask);
                    var decMessage = TweetNaCl.CryptoBoxOpen(encMessage, nonce, apk, bsk);
                }

                using (var context = timer.NewContext("Decryption"))
                {
                    var encMessage = TweetNaCl.CryptoBox(bMessage, nonce, bpk, ask);
                    var decMessage = TweetNaCl.CryptoBoxOpen(encMessage, nonce, apk, bsk);
                }

                //Console.WriteLine(timer.);

            }

            Console.ReadKey();
        }
    }
}
