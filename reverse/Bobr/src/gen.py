import base64


password = input()
s = "TnUgcG9jaGVtdSBib2JyeSB0YWsgZG9icnk/Pz8/Pz8="

if base64.b64encode(password.encode("utf-8")).decode("utf-8") == s:
    data1 = list(map(ord, password))
    data2 = [85, 47, 44, 112, 111, 99, 104, 101, 114, 125, 109, 47, 103, 111, 121, 123, 36, 120, 110, 37, 117, 117, 99, 112, 44, 97, 63, 57, 50, 60, 111, 118]

    data = [data1[i] ^ data2[i] for i in range(32)]
    
    with open("bobr.bin", "wb") as f:
       f.write(bytes(data))
       f.flush()
       print("bobr generated")