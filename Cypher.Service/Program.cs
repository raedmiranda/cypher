using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Cypher.Service
{
    public static class EncryptionHelper
    {
        public static string Encrypt(string originalText)
        {
            string encryptionKey = "globant";
            byte[] originalBytes = Encoding.Unicode.GetBytes(originalText);
            using (Aes encryptor = Aes.Create())
            {
                Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(encryptionKey, new byte[] { 0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76 });
                encryptor.Key = pdb.GetBytes(32);
                encryptor.IV = pdb.GetBytes(16);
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, encryptor.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(originalBytes, 0, originalBytes.Length);
                        cs.Close();
                    }
                    originalText = Convert.ToBase64String(ms.ToArray());
                }
            }
            return originalText;
        }


        public static string Decrypt(string cipherText)
        {
            string EncryptionKey = "globant";
            cipherText = cipherText.Replace(" ", "+");
            byte[] cipherBytes = Convert.FromBase64String(cipherText);
            using (Aes encryptor = Aes.Create())
            {
                Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(EncryptionKey, new byte[] { 0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76 });
                encryptor.Key = pdb.GetBytes(32);
                encryptor.IV = pdb.GetBytes(16);
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, encryptor.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(cipherBytes, 0, cipherBytes.Length);
                        cs.Close();
                    }
                    cipherText = Encoding.Unicode.GetString(ms.ToArray());
                }
            }
            return cipherText;
        }

        static void Main(string[] args)
        {

            Console.WriteLine("Type a text... ");
            string text = Console.ReadLine();
            string encrypted = Encrypt(text);
            string decrypted = Decrypt(encrypted);
            Console.WriteLine("Encrypted: " + encrypted);
            Console.WriteLine("Decrypted: " + decrypted);
        }
    }
}
