import json

from const import PORT, TRAIN_FILE, TEST_FILE, ADDR
from pwn import *
from bottlesolver import BottleSolver
from random import random

solver = BottleSolver()
x_train = []
y_train = []
x_test = []
y_test = []

print("Собираем трейн сет...")
for i in range(15):
    with remote(ADDR, PORT) as r:
        for attempt in range(1000):
            if attempt % 100 == 0:
                print(f"Собрано: train ({len(x_train)}), test ({len(x_test)})")

            try:
                # Получаем данные
                data = r.recvuntil(b'Enter angular velocity: ').decode()

                # Парсим параметры
                features = solver.parse_params(data)

                # Делаем рандомное предсказание
                # prediction = solver.predict(features)

                # Отправляем ответ
                r.sendline(f"10".encode("utf-8"))

                # Получаем результат
                r.recvline()
                correct_line = r.recvline().decode()
                correct = float(correct_line.split()[4])

                # Сохраняем данные: 20% - test, 80% - train
                if random() < 0.2:
                    x_test.append(features)
                    y_test.append(correct)
                else:
                    x_train.append(features)
                    y_train.append(correct)
                # solver.history.append((correct, prediction))  # Исправил порядок значений

                # Обновляем модель
                # solver.update_model()

                # # Обновляем график
                # if attempt % 50 == 0:
                #     solver.update_plot()

                # print(f"Попытка: {attempt+1:04d} | Предсказано: {prediction:0.5f} | Реальное: {correct:0.5f} | Разница: {abs(prediction - correct):0.5f}")

            except EOFError:
                print("Соединение закрыто")
                break
            except Exception as e:
                print(f"Критическая ошибка: {e}")
                break

print(f"Собрано: train ({len(x_train)}), test ({len(x_test)})")

with open(TRAIN_FILE, "w") as f:
    f.write(json.dumps({"x": x_train, "y": y_train}))

with open(TEST_FILE, "w") as f:
    f.write(json.dumps({"x": x_test, "y": y_test}))

print(f"train data saved in '{TRAIN_FILE}'")
print(f"test data saved in '{TEST_FILE}'")