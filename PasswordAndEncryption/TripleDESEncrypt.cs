using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;


namespace PasswordAndEncryption
{

    public static class TripleDESEncrypt
    {

        public static string Encrypt(string plainText, byte[] key, byte[] iv)
        {
            byte[] encrypted;

            using (TripleDES tdes = TripleDES.Create())
            {
                ICryptoTransform encryptor = tdes.CreateEncryptor(key, iv);
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    {
                        byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
                        cs.Write(plainBytes, 0, plainBytes.Length);
                    }
                    encrypted = ms.ToArray();
                }
            }
            return Convert.ToBase64String(encrypted);
        }


        public static string Decrypt(string encryptedTex, byte[] key, byte[] iv)
        {
            byte[] decrypted;

            using (TripleDES tdes = TripleDES.Create())
            {
                ICryptoTransform decryptor = tdes.CreateDecryptor(key, iv);
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Write))
                    {
                        byte[] cipherBytes = Convert.FromBase64String(encryptedTex);
                        cs.Write(cipherBytes, 0, cipherBytes.Length);
                    }
                    decrypted = ms.ToArray();
                }
            }
            return System.Text.Encoding.UTF8.GetString(decrypted);
        }

    }

}