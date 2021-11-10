using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SecurePassword
{
    class Hashing
    {
        private readonly byte[] saltKey;

        public Hashing(byte[] salt)
        {
            saltKey = salt;
        }

        public string ByteToString(byte[] bya)
        {
            return Convert.ToBase64String(bya);
        }
        public byte[] StringToByte(string msg)
        {
            return Convert.FromBase64String(msg);
        }

        public byte[] CreateHash(string psw, int iteration)
        {
            Rfc2898DeriveBytes pbkdf2 = new Rfc2898DeriveBytes(psw, saltKey, iteration);
            return pbkdf2.GetBytes(24);
        }


    

    }
}
