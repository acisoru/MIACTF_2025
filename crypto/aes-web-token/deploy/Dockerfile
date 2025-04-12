FROM python:3.11-slim
WORKDIR /app

RUN pip install Pycryptodome
RUN apt-get update && apt-get install -y socat && apt-get clean

COPY task.py ./

CMD ["socat", "tcp-l:6190,reuseaddr,fork", "EXEC:'python3 task.py',pty,stderr,echo=0"]
