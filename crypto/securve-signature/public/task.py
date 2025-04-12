from rng import SplitMix64
from fastecdsa.curve import P256
from hashlib import sha256
import ast

n = P256.q

rng = SplitMix64()
d = rng.randbelow(n)
Q = d * P256.G

def sign(message):
    z = int.from_bytes(sha256(message.encode()).digest(), 'big')
    k = 1 + rng.randbelow(n - 1)
    P = k * P256.G
    r = P.x
    s = (z + r * d) * pow(k, -1, n) % n
    return r, s

def verify(r, s, message):
    z = int.from_bytes(sha256(message.encode()).digest(), 'big')
    u1 = z * pow(s, -1, n) % n
    u2 = r * pow(s, -1, n) % n
    P = u1 * P256.G + u2 * Q
    return r == P.x


my_database = {
    "name": "maximxls",
    "public_key": Q,
    "flag": "miactf{REDACTEDREDACTEDREDACTEDREDACTEDREDACTEDREDACTEDRED}"
}

while True:
    print("Choose: get_permission, read_database, generate_random_numbers")
    choice = input("> ").strip().lower()
    if choice == "get_permission":
        print("What information do you want to get?")
        key = input("> ").strip().lower()
        if key not in my_database:
            print("No such key!")
            continue
        elif key == "flag":
            print("Flag is confidential! No permission.")
            continue
        print("Here is your permission signature:")
        print(sign(key))
    elif choice == "read_database":
        print("What information do you want to get?")
        key = input("> ").strip().lower()
        if key not in my_database:
            print("No such key!")
            continue
        print("Enter the permission signature for this request.")
        r, s = ast.literal_eval(input("> ").strip())
        if not verify(r, s, key):
            print("Signature is invalid!")
            continue
        print(my_database[key])
    elif choice == "generate_random_numbers":
        print("How many numbers you want me to generate?")
        k = int(input("> ").strip().lower())
        rng.jump(k)
        print("Done.")
    else:
        print("Idk what you want.")


