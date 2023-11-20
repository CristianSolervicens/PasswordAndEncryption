using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace PasswordAndEncryption
{

    /// <summary>
    /// Generates Private and Public RSA Keys
    /// </summary>
    public class NewRSA
    {
        private readonly RSA _rsa;

        public NewRSA()
        {
            _rsa = RSA.Create(2048);
        }
        public NewRSA(byte[] publicKey)
        {
            _rsa = RSA.Create();
            _rsa.ImportRSAPublicKey(publicKey, out _);
        }
        public NewRSA(byte[] publicKey, byte[] encryptedKey, string password)
        {
            _rsa = RSA.Create();
            _rsa.ImportRSAPublicKey(publicKey, out _);
            _rsa.ImportEncryptedPkcs8PrivateKey(Encoding.UTF8.GetBytes(password), encryptedKey, out _);
        }

        //public byte[] Encrypt(string dataToEncrypt)
        //{
        //    return _rsa.Encrypt(Encoding.UTF8.GetBytes(dataToEncrypt), RSAEncryptionPadding.OaepSHA256);
        //}

        public byte[] Encrypt(byte[] dataToEncrypt)
        {
            return _rsa.Encrypt(dataToEncrypt, RSAEncryptionPadding.OaepSHA256);
        }

        public string Encrypt(string dataToEncrypt)
        {
            return Convert.ToBase64String( _rsa.Encrypt(Encoding.UTF8.GetBytes(dataToEncrypt), RSAEncryptionPadding.OaepSHA256));
        }

        public byte[] Decrypt(byte[] dataToDecrypt)
        {
            return _rsa.Decrypt(dataToDecrypt, RSAEncryptionPadding.OaepSHA256);
        }

        public string Decrypt(string dataToDecrypt)
        {
            return Encoding.Default.GetString(_rsa.Decrypt(Convert.FromBase64String(dataToDecrypt), RSAEncryptionPadding.OaepSHA256));
        }

        public byte[] ExportPrivateKey(int numberOfIterations, string password)
        {
            var keyParams = new PbeParameters(
                PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, numberOfIterations);

            var encryptedPrivateKey = _rsa.ExportEncryptedPkcs8PrivateKey(
                Encoding.UTF8.GetBytes(password), keyParams);

            return encryptedPrivateKey;
        }

        public void ImportEncryptedPrivateKey(byte[] encryptedKey, string password)
        {
            _rsa.ImportEncryptedPkcs8PrivateKey(Encoding.UTF8.GetBytes(password), encryptedKey, out _);
        }

        public byte[] ExportPublicKey()
        {
            return _rsa.ExportRSAPublicKey();
        }

        public void ImportPublicKey(byte[] publicKey)
        {
            _rsa.ImportRSAPublicKey(publicKey, out _);
        }
    }
}
