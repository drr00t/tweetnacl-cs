using Metrics;
using Nacl;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NaCl.Bench
{
    class Program
    {
        

        static void Main(string[] args)
        {
            Timer timer = Metric.Timer("Requests", Unit.Requests);

            for (var i = 0; i < 10; i++)
            {
                Byte[] apk = new Byte[TweetNaCl.BOX_PUBLICKEYBYTES];
                Byte[] ask = new Byte[TweetNaCl.BOX_SECRETKEYBYTES];

                Byte[] bpk = new Byte[TweetNaCl.BOX_PUBLICKEYBYTES];
                Byte[] bsk = new Byte[TweetNaCl.BOX_SECRETKEYBYTES];

                String message = "test";
                Byte[] bMessage = Encoding.UTF8.GetBytes(message);
                Byte[] nonce = new Byte[TweetNaCl.BOX_NONCEBYTES];
                Byte[] k = new Byte[TweetNaCl.BOX_BEFORENMBYTES];

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
