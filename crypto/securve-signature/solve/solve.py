from hashlib import sha256
from fastecdsa.curve import P256
from pwn import *
import ast


context.encoding = "ASCII"
context.log_level = "debug"
pi = remote("localhost", 6184)

n = P256.q

pi.sendlineafter("> ", "get_permission")
pi.sendlineafter("> ", "name")
pi.recvuntil("Here is your permission signature:\r\n")
r1, s1 = ast.literal_eval(pi.recvline().decode())

pi.sendlineafter("> ", "generate_random_numbers")
pi.sendlineafter("> ", "18446744073709551612")

pi.sendlineafter("> ", "get_permission")
pi.sendlineafter("> ", "public_key")
pi.recvuntil("Here is your permission signature:\r\n")
r2, s2 = ast.literal_eval(pi.recvline().decode())

z1 = int.from_bytes(sha256("name".encode()).digest(), 'big')
z2 = int.from_bytes(sha256("public_key".encode()).digest(), 'big')

k = (z1 - z2) * pow(s1 - s2, -1, n) % n
d = ((s1 * k) - z1) * pow(r1, -1, n) % n

Q = d * P256.G

def sign(message):
    z = int.from_bytes(sha256(message.encode()).digest(), 'big')
    k = 1337
    P = k * P256.G
    r = P.x
    s = (z + r * d) * pow(k, -1, n) % n
    return r, s

pi.sendlineafter("> ", "read_database")
pi.sendlineafter("> ", "flag")
pi.sendlineafter("> ", str(sign("flag")))

pi.interactive()
