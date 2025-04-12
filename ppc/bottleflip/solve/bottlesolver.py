import os

os.environ["KERAS_BACKEND"] = "torch"

import keras
from keras.src.optimizers import Adam
import numpy as np
from keras import Sequential, Input
from keras.src.layers import Dense, BatchNormalization
from sklearn.preprocessing import StandardScaler
import re

def _build_model():
    model = Sequential([
        Input(shape=(3,)),
        Dense(256, activation='relu'),
        BatchNormalization(),

        Dense(128, activation='tanh'),
        BatchNormalization(),

        Dense(64, activation='relu'),
        Dense(1)
    ])

    model.compile(
        optimizer=Adam(learning_rate=0.001, beta_1=0.9, beta_2=0.999),
        loss='mse',
        metrics=['mae']
    )
    return model

class BottleSolver:
    def __init__(self):
        self.scaler = StandardScaler()
        self.model = _build_model()
        self.X = []
        self.Y = []
        self.history = []
        self.is_trained = False

    def train(self, x, y, batch_size=32, epochs=100):
        try:
            x_train = np.array(x)
            y_train = np.array(y)

            # Обучение модели
            history = self.model.fit(
                x_train,
                y_train,
                epochs=epochs,
                batch_size=batch_size,
                shuffle=True,
                verbose=1,
            )
            self.history.extend(history.history['loss'])

        except Exception as e:
            raise Exception(f"Ошибка обучения модели: {e}")

    def test(self, x, y) -> float:
        x_test = np.array(x)
        y_test = np.array(y)
        # x_scaled = self.scaler.transform(x_test)

        loss, metrics = self.model.evaluate(x_test, y_test)
        return loss

    def predict(self, features):
        try:
            features = np.array(features).reshape(1, -1)
            # features_scaled = self.scaler.transform(features)
            return self.model.predict(features, verbose=0)[0][0]
        except Exception as e:
            raise Exception(f"Ошибка предсказания: {e}")

    def save_model(self, path):
        self.model.save(path)

    def load_model(self, path):
        self.model = keras.models.load_model(path)

    def parse_params(self, data):
        Vb = float(re.search(r"Bottle volume: (\d+\.\d+)L", data).group(1))
        Vw = float(re.search(r"Water volume: (\d+\.\d+)L", data).group(1))
        g = float(re.search(r"Gravity: (\d+\.\d+)m/s²", data).group(1))
        return [Vb, Vw, g]