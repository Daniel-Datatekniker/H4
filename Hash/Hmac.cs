using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Hash
{
    class Hmac
    {
        private HMAC hmac;

        public Hmac(HashTypes types, byte[] Key)
        {
            switch (types)
            {
                case HashTypes.SHA1:
                    hmac = new System.Security.Cryptography.HMACSHA1(Key);
                    break;
                case HashTypes.MD5:
                    hmac = new System.Security.Cryptography.HMACMD5(Key);
                    break;
                case HashTypes.RIPEMD:
                    hmac = new System.Security.Cryptography.HMACRIPEMD160(Key);
                    break;
                case HashTypes.SHA256:
                    hmac = new System.Security.Cryptography.HMACSHA256(Key);
                    break;
                case HashTypes.SHA384:
                    hmac = new System.Security.Cryptography.HMACSHA384(Key);
                    break;
                case HashTypes.SHA512:
                    hmac = new System.Security.Cryptography.HMACSHA512(Key);
                    break;
            }
        }



        public byte[] EncodeUtf8(string msg)
        {
            return Encoding.UTF8.GetBytes(msg);
        }

        public byte[] computeHmac(HashTypes hashTypes, byte[] Unhashed, byte[] key)
        {
            switch (hashTypes)
            {
                case HashTypes.SHA1:
                    return ComputeHmacSha1(Unhashed, key);
                case HashTypes.MD5:
                    return ComputeHmachMd5(Unhashed, key);
                case HashTypes.RIPEMD:
                    return ComputeHmacRipemd(Unhashed, key);
                case HashTypes.SHA256:
                    return ComputeHmacSha256(Unhashed, key);
                case HashTypes.SHA384:
                    return ComputeHmacSha384(Unhashed, key);
                case HashTypes.SHA512:
                    return ComputeHmacSha512(Unhashed, key);
            }
            return new byte[0];
        }

        public byte[] ComputeHmacSha1(byte[] toBeHashed, byte[] key)
        {
            using (var sha1 = new HMACSHA1(key))
            {
                return sha1.ComputeHash(toBeHashed);
            }
        }

        public byte[] ComputeHmacSha256(byte[] toBeHashed, byte[] key)
        {
            using (var sha256 = new HMACSHA256(key))
            {
                return sha256.ComputeHash(toBeHashed);
            }
        }
        public byte[] ComputeHmacRipemd(byte[] toBeHashed, byte[] key)
        {
            using (var emd160 = new HMACRIPEMD160(key))
            {
                return emd160.ComputeHash(toBeHashed);
            }
        }
        public byte[] ComputeHmacSha384(byte[] toBeHashed, byte[] key)
        {
            using (var sha384 = new HMACSHA384(key))
            {
                return sha384.ComputeHash(toBeHashed);
            }
        }
        public byte[] ComputeHmacSha512(byte[] toBeHashed, byte[] key)
        {
            using (var sha512 = new HMACSHA512(key))
            {
                return sha512.ComputeHash(toBeHashed);
            }
        }

        public byte[] ComputeHmachMd5(byte[] toBeHashed, byte[] key)
        {
            using (var md5 = new HMACMD5(key))
            {
                return md5.ComputeHash(toBeHashed);
            }
        }

        public bool CheckAuthority(byte[] mes, byte[] mac, byte[] key)
        {
            hmac.Key = key;
            return CompareByteArray(hmac.ComputeHash(mes), mac, hmac.HashSize / 8 );
        }

        public byte[] ComputeMac(byte[] mes, byte[] key)
        {
            hmac.Key = key;
            return hmac.ComputeHash(mes);
        }
        private bool CompareByteArray(byte[] b1, byte[] b2, int lengt)
        {
            for (int i = 0; i < lengt; i++)
                if (b1[i] != b2[i])
                    return false;

            return true;
        }

    }
}
