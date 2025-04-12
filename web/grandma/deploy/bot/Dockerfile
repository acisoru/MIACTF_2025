FROM python:3.10

ADD . /bot

WORKDIR /bot
RUN pip install -r requirements.txt --no-cache-dir

ENTRYPOINT ["python3", "main.py"]

