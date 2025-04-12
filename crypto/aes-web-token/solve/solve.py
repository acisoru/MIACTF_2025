from pwn import *
from json import dumps
from Crypto.Util.Padding import pad
from base64 import b64encode
import ast


context.encoding = "ASCII"
context.log_level = "debug"
pi = remote("localhost", 6190)


tok_bytes = pad(dumps({"username": "maximxls", "is_admin": 1, "can_access_flag": 1}).encode(), 16)

ct_bytes = bytearray(len(tok_bytes) + 16)

pi.sendlineafter("token>", b64encode(ct_bytes))

pi.recvuntil("Token ")
pt_bytes = ast.literal_eval(pi.recvuntil(" is bad.", True).decode())


for i in reversed(range(0, len(tok_bytes), 16)):
    ct_bytes[i:i+16] = bytes(x ^ y for x, y in zip(pt_bytes[i:i+16], tok_bytes[i:i+16]))

    pi.sendlineafter("token>", b64encode(ct_bytes))

    if pi.recvuntil(["Token ", "Hello"]).endswith(b"Hello"):
        break
    pt_bytes = ast.literal_eval(pi.recvuntil(" is bad.", True).decode())
else:
    pi.sendlineafter("token>", b64encode(ct_bytes))

pi.sendlineafter(">", "get flag")

print(pi.recvline().decode())


