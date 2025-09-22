using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Text; // [OPDATERET] brug UTF8

namespace PasswordCrackerCentralized.util
{
    class PasswordFileHandler
    {
        /// <summary>
        /// [OPDATERET] Skriv passwordfil med SHA1(Base64) pr. linje: username:BASE64(hash)
        /// - Bruger FileMode.Create (ikke CreateNew)
        /// - Bruger UTF8 i stedet for Char->byte (rigtigt for æ/ø/å)
        /// - Ingen ekstra "\n" oveni WriteLine
        /// </summary>
        public static void WritePasswordFile(string filename, string[] usernames, string[] passwords)
        {
            HashAlgorithm messageDigest = new SHA1CryptoServiceProvider();
            if (usernames.Length != passwords.Length)
                throw new ArgumentException("usernames and passwords must be same lengths");

            using (FileStream fs = new FileStream(filename, FileMode.Create, FileAccess.Write))
            using (StreamWriter sw = new StreamWriter(fs, Encoding.UTF8)) // [OPDATERET]
            {
                for (int i = 0; i < usernames.Length; i++)
                {
                    byte[] passwordAsBytes = Encoding.UTF8.GetBytes(passwords[i]); // [OPDATERET]
                    byte[] encryptedPassword = messageDigest.ComputeHash(passwordAsBytes);
                    string line = usernames[i] + ":" + Convert.ToBase64String(encryptedPassword);
                    sw.WriteLine(line);
                }
            }
        }

        /// <summary>
        /// [OPDATERET] Robust læsning af passwordfil:
        /// - UTF8
        /// - Ignorerer tomme/defekte linjer
        /// - Split max 2 dele
        /// </summary>
        public static List<model.UserInfo> ReadPasswordFile(string filename)
        {
            List<model.UserInfo> result = new List<model.UserInfo>();

            using (FileStream fs = new FileStream(filename, FileMode.Open, FileAccess.Read))
            using (StreamReader sr = new StreamReader(fs, Encoding.UTF8)) // [OPDATERET]
            {
                while (!sr.EndOfStream)
                {
                    string line = sr.ReadLine()?.Trim();
                    if (string.IsNullOrEmpty(line)) continue;

                    string[] parts = line.Split(':', 2); // [OPDATERET]
                    if (parts.Length != 2)
                    {
                        Console.WriteLine("Skipping malformed line: " + line);
                        continue;
                    }

                    try
                    {
                        var userInfo = new model.UserInfo(parts[0], parts[1]);
                        result.Add(userInfo);
                    }
                    catch (FormatException)
                    {
                        Console.WriteLine("Bad Base64 for line: " + line);
                    }
                }
            }
            return result;
        }
    }
}
