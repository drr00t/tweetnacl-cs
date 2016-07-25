using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TweetNaCl.Tests
{
    [TestFixture]
    public class TweetNaClTests
    {
        [Test]
        public void UInt32ToByteArray()
        {
            UInt32 u = 32678;
            Byte[] x = new Byte[4];
            UInt32[] x1 = new UInt32[4];

            for (var i = 0; i < 4; ++i) 
            { 
                x[i] = (byte)u; 
                x1[i] = u; u >>= 8; 
            }
        }
    }
}
