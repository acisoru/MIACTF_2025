FROM python:3.11-slim

# Установка g++ и нужных утилит
RUN apt-get update && \
    apt-get install -y --no-install-recommends g++ && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Установка Python-зависимостей
RUN pip install --no-cache-dir pyTelegramBotAPI

# Установка рабочей директории
WORKDIR /app

# Копируем всё внутрь контейнера
COPY . .

# Компиляция C++ файлов
RUN g++ -O2 -o check_history check_history.cpp && \
    g++ -O2 -o check_compliment check_compliment.cpp && \
    g++ -O2 -o check_place check_place.cpp

# Даём права на выполнение (на всякий случай)
RUN chmod +x check_history check_compliment check_place

# Запуск бота
CMD ["python", "main.py"]
