from pwn import *
from bottlesolver import BottleSolver
from const import ADDR, PORT


def main():
    solver = BottleSolver()
    solver.load_model("model.keras")

    with remote(ADDR, PORT) as r:
        print("Собираем трейн сет...")
        for attempt in range(1000):
            try:
                # Получаем данные
                data = r.recvuntil(b'Enter angular velocity: ').decode()

                # Парсим параметры
                features = solver.parse_params(data)

                # Делаем предсказание
                prediction = solver.predict(features)

                # Отправляем ответ
                r.sendline(f"{prediction:.5f}".encode("utf-8"))

                # Получаем результат
                r.recvline()
                correct_line = r.recvline().decode()
                correct = float(correct_line.split()[4])

                print(f"Попытка: {attempt+1:04d} | Предсказано: {prediction:0.5f} | Реальное: {correct:0.5f} | Разница: {abs(prediction - correct):0.5f}")

            except EOFError:
                print("Соединение закрыто")
                break
            except Exception as e:
                print(f"Критическая ошибка: {e}")
                break
        r.interactive()
if __name__ == "__main__":
    main()