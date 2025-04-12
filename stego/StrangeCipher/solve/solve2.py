from base64 import b64decode as b64d

enc = b'srauqLu1gEt4s7t7rHuzVXuse7NVe6xEt1tZfreC'
enc = b64d(enc)
flag = ''

for i in enc:
    flag += chr((i ^ 37) - 42)

print(flag)
