import json
from os.path import exists
from bottlesolver import BottleSolver
from const import TEST_FILE, TRAIN_FILE, MODEL_FILE

with open(TEST_FILE, "r") as f:
    test_data = json.load(f)
    x_test, y_test = test_data["x"], test_data["y"]

with open(TRAIN_FILE, "r") as f:
    train_data = json.load(f)
    x_train, y_train = train_data["x"], train_data["y"]

print(f"train length: {len(x_train)}, test length: {len(x_test)}")

solver = BottleSolver()
if exists(MODEL_FILE) and input(f"Load pre-trained model({MODEL_FILE}? (y/n): ").lower() == "y":
    print("Loading model...")
    solver.load_model(MODEL_FILE)
else:
    print("Training model from scratch...")


solver.train(x_train, y_train, batch_size=256, epochs=100)

err = solver.test(x_test, y_test)
print("test err:", err)

solver.save_model(MODEL_FILE)

# update_plot(history, ax)


