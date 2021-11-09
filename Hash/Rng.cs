using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Hash
{
    class Rng
    {
        public byte[] KeyGenerator(int length)
        {
            using (var rng = new RNGCryptoServiceProvider())
            {
                byte[] data = new byte[12];
                for (int i = 0; i < length; i++)
                    rng.GetBytes(data);
                return data;
            }
        }
    }
}
