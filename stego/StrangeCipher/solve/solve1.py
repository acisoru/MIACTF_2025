from PIL import Image
image = Image.open("StrangeCipher.png")
x, y = image.size
for i in range(y):
    for j in range(x):  
        a = image.getpixel((j, i))[3]
        if a != 255:
            print(chr(a), end='')

