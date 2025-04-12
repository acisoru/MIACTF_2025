import os
from Crypto.Cipher import AES
from json import loads, dumps
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode


FLAG = "miactf{p1s_d0n7_us3_AES_f0r_0th3r_purp0s3s_w1th0ut_th1nk1ng}"
SECRET_KEY = os.urandom(32)


def issue_token(username, is_admin=False, can_access_flag=False):
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC)
    token_data = dumps({"username": username, "is_admin": is_admin, "can_access_flag": can_access_flag})
    return b64encode(cipher.iv + cipher.encrypt(pad(token_data.encode(), AES.block_size))).decode()


def get_token_data(token):
    try:
        token = b64decode(token)
        iv, token = token[:16], token[16:]
        cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv)
        token = cipher.decrypt(token)
        token_data = loads(unpad(token, AES.block_size).decode())
    except Exception as e:
        raise ValueError(f"Token {token} is bad.") from e
    return token_data


print("Please log in with a token.")

while True:
    token = input("token> ")
    try:
        token_data = get_token_data(token)
    except Exception as e:
        print(e)
        continue
    print(f"Hello, {token_data['username']}.")
    while True:
        inp = input("> ").strip()
        if inp == "get flag":
            if token_data['is_admin'] and token_data['can_access_flag']:
                print(FLAG)
            else:
                print("You lack permission.")
        else:
            print("I understand.")
