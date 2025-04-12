def decode_f(key, andValue, orValue):
    key = bin(key)[2:]
    andValue = '0' * (len(key) - len(bin(andValue)[2:])) + bin(andValue)[2:]
    orValue = '0' * (len(key) - len(bin(orValue)[2:])) + bin(orValue)[2:]
    res = ''
    for i in range(len(key)):
        if andValue[i] == '1':
            res += '1'
        elif key[i] == '0' and andValue[i] == '0' and orValue[i] == '0':
            res += '0'
        elif key[i] == '1' and andValue[i] == '0' and orValue[i] == '1':
            res += '0'
        elif key[i] == '0' and andValue[i] == '0' and orValue[i] == '1':
            res += '1'
        elif key[i] == '1' and andValue[i] == '1':
            res += '1'
    return chr(int(res, 2))

flag = ''
with open('encoded.txt') as file:
    s = [[int(j) for j in i.split()] for i in file.readlines()]

for key in range(1, 100000):
    res = ''
    for i in s:
        res += decode_f(key, i[0], i[1])
    if 'miactf' in res:
        print(res)
        break

