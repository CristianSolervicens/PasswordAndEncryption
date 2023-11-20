using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace PasswordAndEncryption
{
    public static class AesGcmEncryption
    {
        public static (string, string) Encrypt(string dataToEncrypt, byte[] key, byte[] nonce, string metadata)
        {
            var _dataToEncrypt = Encoding.UTF8.GetBytes(dataToEncrypt);
            var associatedData = Encoding.UTF8.GetBytes(metadata);
            // these will be filled during the encryption
            var tag = new byte[16];
            var ciphertext = new byte[_dataToEncrypt.Length];

            using var aesGcm = new AesGcm(key);
            aesGcm.Encrypt(nonce, _dataToEncrypt, ciphertext, tag, associatedData);

            return (Convert.ToBase64String(ciphertext), Convert.ToBase64String(tag));
        }

        public static string Decrypt(string cipherText, byte[] key, byte[] nonce, string tag, string metadata)
        {
            var _tag = Convert.FromBase64String(tag);
            var associatedData = Encoding.UTF8.GetBytes(metadata);
            var _cipherText = Convert.FromBase64String(cipherText);
            var decryptedData = new byte[_cipherText.Length];

            using var aesGcm = new AesGcm(key);
            aesGcm.Decrypt(nonce, _cipherText, _tag, decryptedData, associatedData);

            return System.Text.Encoding.UTF8.GetString(decryptedData);
        }
    }

}