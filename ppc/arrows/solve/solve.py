from detection import *
from pwn import *
import base64

def draw_direction(image, bbox, direction):
    (x, y), (w, h) = bbox[0], bbox[1]

    # Нарисовать bounding box
    cv2.rectangle(image, (x, y), (x + w, y + h), (0, 0, 255), 2)

    # Определить начальные и конечные координаты стрелки
    if direction == "UP":
        start_x, start_y, end_x, end_y = x + w // 2, y + h, x + w // 2, y
    elif direction == "DOWN":
        start_x, start_y, end_x, end_y = x + w // 2, y, x + w // 2, y + h
    elif direction == "LEFT":
        start_x, start_y, end_x, end_y = x + w, y + h // 2, x, y + h // 2
    elif direction == "RIGHT":
        start_x, start_y, end_x, end_y = x, y + h // 2, x + w, y + h // 2
    else:
        return

    # Нарисовать стрелку
    cv2.arrowedLine(image, (start_x, start_y), (end_x, end_y), (0, 0, 255), 3, tipLength=0.3)

HOST = "localhost"
PORT = 10019

if __name__ == "__main__":
    templates = load_templates()

    conn = remote(HOST, PORT)

    intro_msg = conn.recvuntil(b"Press [ENTER] to start...")
    print(intro_msg.decode())

    conn.sendline(b"")

    while True:
        try:
            img_data_b64 = conn.recvline().strip()

            img_data = base64.b64decode(img_data_b64)

            nparr = np.frombuffer(img_data, np.uint8)
            img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)

            direction_info = conn.recvuntil(b"Direction: ")
            print(direction_info.decode())

            direction, loc_info = detect_direction(img, templates)
            if direction == "UNKNOWN":
                conn.sendline(b"RIGHT")
                continue

            draw_direction(img, loc_info, direction)

            cv2.imshow("Captcha", img)
            cv2.waitKey(1)

            conn.sendline(direction.encode())
        except Exception as e:
            print(e)
            conn.interactive()