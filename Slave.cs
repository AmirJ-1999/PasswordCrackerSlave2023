// FILE: PasswordCrackerSlave2023/Slave.cs
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace PasswordCrackerSlave2023
{
    internal class Slave
    {
        internal void connect(string host, int port)
        {
            using (TcpClient client = new TcpClient(host, port))
            using (Stream ns = client.GetStream())
            using (StreamReader sr = new StreamReader(ns, Encoding.UTF8))
            using (StreamWriter sw = new StreamWriter(ns, Encoding.UTF8) { AutoFlush = true })
            {
                sw.WriteLine("chunk"); // bed om chunk

                string response = sr.ReadLine();
                if (string.IsNullOrWhiteSpace(response))
                {
                    Console.WriteLine("Empty response from master.");
                    return;
                }

                Console.WriteLine("Raw response length: " + response.Length);
                Console.WriteLine("Raw preview: " + response.Substring(0, Math.Min(120, response.Length)));

                List<string> chunk = JsonSerializer.Deserialize<List<string>>(response);
                if (chunk == null)
                {
                    Console.WriteLine("Received null chunk!");
                    return;
                }

                Console.WriteLine($"Received chunk with {chunk.Count} words.");
                for (int i = 0; i < Math.Min(5, chunk.Count); i++)
                    Console.WriteLine($"[{i}] {chunk[i]}");

                RunCracker(chunk);
            }
        }

        private void RunCracker(List<string> chunk)
        {
            var userInfos = ReadPasswordFile("passwords.txt"); // LOKAL fil i Slave-mappen
            Console.WriteLine($"Starting cracking on chunk of {chunk.Count} words against {userInfos.Count} hashes...");

            var found = new ConcurrentBag<UserInfoClearText>();

            Parallel.ForEach(
                chunk,
                () => (HashAlgorithm)new SHA1CryptoServiceProvider(),
                (dictionaryEntry, loopState, localHash) =>
                {
                    void CheckSingle(string candidate)
                    {
                        byte[] bytes = Encoding.UTF8.GetBytes(candidate);
                        byte[] hash = localHash.ComputeHash(bytes);

                        foreach (var u in userInfos)
                        {
                            if (CompareBytes(u.EntryptedPassword, hash))
                                found.Add(new UserInfoClearText(u.Username, candidate));
                        }
                    }

                    CheckSingle(dictionaryEntry);
                    CheckSingle(dictionaryEntry.ToUpper());
                    CheckSingle(Capitalize(dictionaryEntry));
                    CheckSingle(Reverse(dictionaryEntry));

                    for (int i = 0; i < 100; i++) CheckSingle(dictionaryEntry + i);
                    for (int i = 0; i < 100; i++) CheckSingle(i + dictionaryEntry);
                    for (int i = 0; i < 10; i++)
                        for (int j = 0; j < 10; j++)
                            CheckSingle(i + dictionaryEntry + j);

                    return localHash;
                },
                localHash => { localHash.Dispose(); }
            );

            foreach (var r in found)
                Console.WriteLine("FOUND: " + r.ToString());

            Console.WriteLine("Done with this chunk.");
        }

        private static bool CompareBytes(IList<byte> a, IList<byte> b)
        {
            if (a == null || b == null || a.Count != b.Count) return false;
            for (int i = 0; i < a.Count; i++) if (a[i] != b[i]) return false;
            return true;
        }

        private static string Capitalize(string str)
        {
            if (string.IsNullOrWhiteSpace(str)) return str;
            if (str.Length == 1) return str.ToUpper();
            return char.ToUpper(str[0]) + str.Substring(1);
        }

        private static string Reverse(string str)
        {
            if (string.IsNullOrEmpty(str)) return str;
            char[] arr = str.ToCharArray();
            Array.Reverse(arr);
            return new string(arr);
        }

        // ===== Lokale modeller og fil-læser (ingen afhængigheder) =====

        [Serializable]
        private class UserInfo
        {
            public string Username { get; set; }
            public string EntryptedPasswordBase64 { get; set; }
            public byte[] EntryptedPassword { get; set; }

            public UserInfo(string username, string base64)
            {
                Username = username ?? throw new ArgumentNullException(nameof(username));
                EntryptedPasswordBase64 = base64 ?? throw new ArgumentNullException(nameof(base64));
                EntryptedPassword = Convert.FromBase64String(base64);
            }
        }

        private class UserInfoClearText
        {
            public string UserName { get; set; }
            public string Password { get; set; }
            public UserInfoClearText(string u, string p) { UserName = u; Password = p; }
            public override string ToString() => UserName + ": " + Password;
        }

        private static List<UserInfo> ReadPasswordFile(string filename)
        {
            var result = new List<UserInfo>();
            using (FileStream fs = new FileStream(filename, FileMode.Open, FileAccess.Read))
            using (StreamReader sr = new StreamReader(fs, Encoding.UTF8))
            {
                while (!sr.EndOfStream)
                {
                    string line = sr.ReadLine()?.Trim();
                    if (string.IsNullOrEmpty(line)) continue;
                    string[] parts = line.Split(':', 2);
                    if (parts.Length != 2) { Console.WriteLine("Skip malformed: " + line); continue; }
                    try { result.Add(new UserInfo(parts[0], parts[1])); }
                    catch (FormatException) { Console.WriteLine("Bad Base64: " + line); }
                }
            }
            return result;
        }
    }
}
