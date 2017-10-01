using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace EncryptionExample
{
    class Program
    {

        private static List<byte[]> encrypted = new List<byte[]>();

        static void Main(string[] args)
        {

            do
            {

                var line = Console.ReadLine();

                if (line == "exit")
                {
                    break;
                }

                var lineEnc = Encrypt(line, "12345678901234567890", "123456789012");

                Console.WriteLine(lineEnc);

                var t1 = Tokenise(new UIElementTokenModel()
                {
                    ProcessFunctionNumber = 123, //processFunctionNumber.Value,
                    ParentKeyNumber = 456, //parentKeyNumber,
                    MenuItemNumber = 789, //menuItemNumber,
                    AllowOverrideMaxRecords = false
                });

                Console.WriteLine(t1);

                var t2 = Tokenise(new UIElementTokenModel()
                {
                    ProcessFunctionNumber = 123, //processFunctionNumber.Value,
                    ParentKeyNumber = 456, //parentKeyNumber,
                    MenuItemNumber = 789, //menuItemNumber,
                    AllowOverrideMaxRecords = false
                });

                Console.WriteLine(t2);

            } while (true);

        }

        private static string Tokenise<T>(T obj)
        {
            return EncryptWeak(JsonConvert.SerializeObject(obj));
        }

        public static string EncryptWeak(string text)
        {
            return EncryptWeak(text, "12345678901234567890", "123456789012");
        }

        /// <summary>
        /// Encrypts a string using AES symmetric algorithm and key derived from specified password and salt.
        /// Result is a base-64 string, suitable for storage, URIs etc.
        /// </summary>
        public static string EncryptWeak(string text, string password, string salt)
        {
            string encryptedString = null;
            // null encrypts to null.
            if (text != null)
            {
                // Convert text to bytes.
                byte[] textBytes = new UTF8Encoding(false).GetBytes(text);
                if (salt == null) salt = "";
                byte[] saltBytes = new UTF8Encoding(false).GetBytes(salt);
                if (saltBytes.Length < 8)
                    throw new ArgumentException("Encryption salt must encode to at least 8 bytes.");
                // Encryption algorithm.
                using (AesManaged aes = new AesManaged())
                {
                    if (password == null) password = "";
                    // Use the PBKDF2 standard for password-based key generation.
                    using (PasswordDeriveBytes kd = new PasswordDeriveBytes(password, saltBytes))
                    {
                        aes.Key = kd.GetBytes(aes.KeySize / 8);
                        aes.IV = kd.GetBytes(aes.BlockSize / 8);
                    }
                    // Encryption.
                    using (ICryptoTransform encryptTransform = aes.CreateEncryptor())
                    {
                        // Output stream.
                        using (MemoryStream memoryStream = new MemoryStream())
                        {
                            using (CryptoStream encryptor = new CryptoStream(memoryStream, encryptTransform, CryptoStreamMode.Write))
                            {
                                encryptor.Write(textBytes, 0, textBytes.Length);
                                encryptor.FlushFinalBlock();
                                encryptor.Close();
                            }

                            encrypted.Add(memoryStream.ToArray());

                            // Convert bytes to base-64 string.
                            encryptedString = Convert.ToBase64String(memoryStream.ToArray());
                        }
                    }
                }
            }
            return encryptedString;
        }

        /// <summary>
        /// Encrypts a string using AES symmetric algorithm and key derived from specified password and salt.
        /// Result is a base-64 string, suitable for storage, URIs etc.
        /// </summary>
        public static string Encrypt(string text, string password, string salt)
        {
            string encryptedString = null;
            // null encrypts to null.
            if (text != null)
            {
                // Convert text to bytes.
                byte[] textBytes = new UTF8Encoding(false).GetBytes(text);
                if (salt == null) salt = "";
                byte[] saltBytes = new UTF8Encoding(false).GetBytes(salt);
                if (saltBytes.Length < 8)
                    throw new ArgumentException("Encryption salt must encode to at least 8 bytes.");
                // Encryption algorithm.
                using (AesManaged aes = new AesManaged())
                {
                    if (password == null) password = "";
                    // Use the PBKDF2 standard for password-based key generation.
                    using (Rfc2898DeriveBytes kd = new Rfc2898DeriveBytes(password, saltBytes))
                    {
                        aes.Key = kd.GetBytes(aes.KeySize / 8);
                        aes.IV = kd.GetBytes(aes.BlockSize / 8);
                    }
                    // Encryption.
                    using (ICryptoTransform encryptTransform = aes.CreateEncryptor())
                    {
                        // Output stream.
                        using (MemoryStream memoryStream = new MemoryStream())
                        {
                            using (CryptoStream encryptor = new CryptoStream(memoryStream, encryptTransform, CryptoStreamMode.Write))
                            {
                                encryptor.Write(textBytes, 0, textBytes.Length);
                                encryptor.FlushFinalBlock();
                                encryptor.Close();
                            }
                            // Convert bytes to base-64 string.
                            encryptedString = Convert.ToBase64String(memoryStream.ToArray());
                        }
                    }
                }
            }
            return encryptedString;
        }

    }
}
