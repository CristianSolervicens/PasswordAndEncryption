using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace PasswordAndEncryption
{
    /// <summary>
    /// Clase para encripta las Contraseñas, sin REVERSIBILIDAD
    /// Se recomienda un número de Iteraciones (Rounds) mayor a 1 millon
    /// </summary>
    public class Password
    {
        private byte[] Salt;
        public string HashedPassWord { get; private set; }
        public int Rounds { get; private set; }


        public Password()
        {
            this.Rounds = 1107503;
        }

        public Password(int numberOfRounds)
        {
            this.Rounds = numberOfRounds;
        }


        /// <summary>
        /// Genera un Salt RANDOM
        /// </summary>
        /// <returns></returns>
        public string GetStringSalt()
        {
            return Convert.ToBase64String(this.Salt);
        }


        public string SaltInitialize()
        {
            this.Salt = RandomNumberGenerator.GetBytes(32);
            return Convert.ToBase64String(this.Salt);
        }


        /// <summary>
        /// Retorna el Hash de la Contraseña, con un Salt RANDOM que se debe rescatar
        /// con el método GetStringSalt()
        /// </summary>
        /// <param name="passwordToHash"></param>
        /// <returns></returns>
        public string PasswordHash(string passwordToHash)
        {
            var sw = Stopwatch.StartNew();
            
            char[] stringArray = passwordToHash.ToCharArray();
            Array.Reverse(stringArray);
            passwordToHash = new string(stringArray);
            
            this.Salt = RandomNumberGenerator.GetBytes(32);

            var hashedPassword = Rfc2898DeriveBytes.Pbkdf2(
                                    passwordToHash,
                                    this.Salt,
                                    this.Rounds,
                                    HashAlgorithmName.SHA256,
                                    32);

            sw.Stop();

            Console.WriteLine();
            Console.WriteLine($"Password to hash : {passwordToHash}");
            Console.WriteLine($"Hashed Password : {Convert.ToBase64String(hashedPassword)}");
            Console.WriteLine($"Iterations < {this.Rounds} > Elapsed Time : {sw.ElapsedMilliseconds} ms");
            return Convert.ToBase64String(hashedPassword);
        }

        /// <summary>
        /// Genera un Hash para la Contraseña y el Salt indicado
        /// </summary>
        /// <param name="passwordToHash"></param>
        /// <param name="sSalt"></param>
        /// <returns></returns>
        public string PasswordHash(string passwordToHash, string sSalt)
        {
            var sw = Stopwatch.StartNew();
            this.Salt = Convert.FromBase64String(sSalt);

            char[] stringArray = passwordToHash.ToCharArray();
            Array.Reverse(stringArray);
            passwordToHash = new string(stringArray);

            var hashedPassword = Rfc2898DeriveBytes.Pbkdf2(
                                    passwordToHash,
                                    this.Salt,
                                    this.Rounds,
                                    HashAlgorithmName.SHA256,
                                    32);

            sw.Stop();

            Console.WriteLine();
            Console.WriteLine($"Password to hash : {passwordToHash}");
            Console.WriteLine($"Hashed Password : {Convert.ToBase64String(hashedPassword)}");
            Console.WriteLine($"Iterations < {this.Rounds} > Elapsed Time : {sw.ElapsedMilliseconds} ms");
            return Convert.ToBase64String(hashedPassword);
        }

    }


}
