using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Decrypt_DLL
{
     internal class Program
    {
        static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                Console.Write("Please specify file that you want to decrypt.");
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
                Decrypt(args[0]);
            }

            Console.ReadLine();
        }

        static void Decrypt(string payloadPath)
        {
            Console.Write("Starting to read payload file.\n");
            // Read content of a file to byte array.
            byte[] fileBytes;
            using (FileStream
                fileStream = new FileStream(payloadPath, FileMode.Open, FileAccess.Read))
            {
                fileBytes = new byte[fileStream.Length];
                fileStream.Read(fileBytes, 0, fileBytes.Length);
            }

            // Define arrays.
            byte[] key = new byte[32];
            byte[] IV = new byte[16];
            byte[] payload = new byte[fileBytes.Length - key.Length - IV.Length];

            // Copy parts.
            Array.Copy(fileBytes, 0, key, 0, key.Length);
            Array.Copy(fileBytes, key.Length, IV, 0, IV.Length);
            Array.Copy(fileBytes, key.Length + IV.Length, payload, 0, payload.Length);




            // Decrypt data.
            byte[] decryptedData = DecryptAes(payload, key, IV);

            Console.WriteLine($"Decoded form is:\n{decryptedData}");

            string outputPath = ".\\decoded.dll";
            if (File.Exists(outputPath))
            {
                Console.WriteLine($"File {outputPath} already exists. Removing it.");
                File.Delete(outputPath);
            }

            // Write output to file
            Console.WriteLine($"Writing encoded key, IV and payload to \"{outputPath}\".");
            // StreamWriter streamW = new StreamWriter(outputPath);
            // streamW.Write(decryptedData);
            // streamW.Close();
            using (FileStream fileStream = new FileStream(outputPath, FileMode.Create))
            {
                fileStream.Write(payload, 0, payload.Length);
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
                    }
                    return ms.ToArray();
                }
            }
        }
    }
}
