using System;
using System.IO;
using System.Text;
using System.Linq;
using System.Security.Cryptography;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace SharpSilentChrome
{
    static class HmacUtils
    {
        public static void RemoveEmpty(JToken token)
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
                              val.Type == JTokenType.Boolean && val.ToObject<bool>() == false ||
                              val.Type == JTokenType.Integer && val.ToObject<long>() == 0) && val.Type != JTokenType.Boolean && val.Type != JTokenType.Integer)
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
                              item.Type == JTokenType.Boolean && item.ToObject<bool>() == false ||
                              item.Type == JTokenType.Integer && item.ToObject<long>() == 0) && item.Type != JTokenType.Boolean && item.Type != JTokenType.Integer)
                        item.Remove();
                }
            }
        }

        public static string CalculateHMAC(JToken value, string path, string sid, byte[] seed)
        {
            if (value.Type == JTokenType.Object || value.Type == JTokenType.Array)
                RemoveEmpty(value);

            string json = JsonConvert.SerializeObject(value, new JsonSerializerSettings
            {
                Formatting = Formatting.None,
                StringEscapeHandling = StringEscapeHandling.Default // Don't escape non-ASCII
            });

            // Apply replacements 
            json = json.Replace("<", "\\u003C").Replace("\\u2122", "™");

            string message = sid + path + json;

            var messageBytes = Encoding.UTF8.GetBytes(message);

            using (var hmac = new HMACSHA256(seed))
            {
                byte[] hash = hmac.ComputeHash(messageBytes);
                var result = BitConverter.ToString(hash).Replace("-", "").ToUpperInvariant();
                return result;
            }
        }

        public static string CalculateChromeDevMac(byte[] seed, string sid, string prefPath, object prefValue)
        {
            var serialized = JsonConvert.SerializeObject(prefValue, new JsonSerializerSettings
            {
                Formatting = Formatting.None
            });

            var input = Encoding.UTF8.GetBytes(sid + prefPath + serialized);
            using (var hmac = new HMACSHA256(seed))
            {
                var hash = hmac.ComputeHash(input);
                return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
            }
        }

        public static string CalcSuperMac(string filePath, string sid, byte[] seed)
        {
            var text = File.ReadAllText(filePath, Encoding.UTF8);
            var data = JObject.Parse(text);
            var macs = data["protection"]["macs"];

            // Serialize like Python: compact JSON with no spaces
            var json = JsonConvert.SerializeObject(macs, new JsonSerializerSettings
            {
                Formatting = Formatting.None
            }).Replace(" ", "");

            var msg = sid + json;
            using (var hmac = new HMACSHA256(seed))
            {
                var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(msg));
                return BitConverter.ToString(hash).Replace("-", "").ToUpperInvariant();
            }
        }
    }
}