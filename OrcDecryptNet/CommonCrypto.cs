using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;

namespace OrcDecryptNet
{
    public static class CommonCrypto
    {
        public static RSA LoadPrivateKeyFromPfx(string privateKeyPath, string password)
        {
            var cert = new X509Certificate2(privateKeyPath, password, X509KeyStorageFlags.Exportable);
            var rsa = cert.GetRSAPrivateKey();
            if (rsa == null)
            {
                throw new Exception("Cannot load private key from PFX");
            }
            return rsa;

        }

        public static string DecodeOid(byte[] oid)
        {
            if (!(oid[0] == 6 && oid[1] == oid.Length - 2))
            {
                throw new ArgumentException(
                    $"Not an OID: {BitConverter.ToString(oid)}. Check first byte ({oid[0]}) and length {oid.Length - 2} with second byte ({oid[1]})."
                );
            }

            List<int> res = new List<int>();
            res.Add(oid[2] / 40);
            res.Add(oid[2] % 40);
            int cur = 0;

            for (int i = 3; i < oid.Length; i++)
            {
                byte tmp = oid[i];
                cur <<= 7;
                if ((tmp & 0x80) != 0)
                {
                    cur |= tmp & 0x7F;
                }
                else
                {
                    cur |= tmp;
                    res.Add(cur);
                    cur = 0;
                }
            }

            return string.Join(".", res);
        }

        public static SymmetricAlgorithm GetCipher(string oid, byte[] key, byte[] iv)
        {
            SymmetricAlgorithm cipher;

            if (oid == "2.16.840.1.101.3.4.1.42")  // AES-256-CBC
            {
                cipher = Aes.Create();
                cipher.KeySize = 256;
                cipher.Key = key;
                cipher.IV = iv;
                cipher.Mode = CipherMode.CBC;
            }
            else if (oid == "2.16.840.1.101.3.4.1.2")  // AES-128-CBC
            {
                cipher = Aes.Create();
                cipher.KeySize = 128;
                cipher.Key = key;
                cipher.IV = iv;
                cipher.Mode = CipherMode.CBC;
            }
            else if (oid == "1.2.840.113549.3.7")  // 3DES-CBC
            {
                cipher = TripleDES.Create();
                cipher.Key = key;
                cipher.IV = iv;
                cipher.Mode = CipherMode.CBC;
            }
            else
            {
                throw new NotImplementedException($"Unknown encryption algorithm with OID {oid}");
            }

            return cipher;
        }

    }
}
