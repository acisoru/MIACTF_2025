FROM vulhub/redis:5.0.7

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y git build-essential pkg-config libcurl4-openssl-dev supervisor

COPY --from=golang:1.23-alpine /usr/local/go/ /usr/local/go/

ENV PATH="/usr/local/go/bin:${PATH}"

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY *.go .
COPY flag.txt /

RUN CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -o main .

RUN useradd -s /bin/rbash readonlyuser

RUN mkdir -p /home/readonlyuser/bin && chown readonlyuser:readonlyuser /home/readonlyuser && \
    chmod 755 /home/readonlyuser/bin

RUN echo "PATH=$HOME/bin" >> /home/readonlyuser/.bashrc && \
    echo "export PATH >> /home/readonlyuser/.bashrс" \
    chattr +i /home/readonlyuser/.bashrc

RUN echo "PATH=$HOME/bin" >> /home/readonlyuser/.bash_profile && \
    echo "export PATH >> /home/readonlyuser/.bash_profile" \
    chattr +i /home/readonlyuser/.bash_profile

RUN ln -s /bin/cat /home/readonlyuser/bin/ && \
    ln -s /bin/ls /home/readonlyuser/bin/ && \
    ln -s /bin/whoami /home/readonlyuser/bin/

RUN rm -rf /bin/kill /usr/bin/kill /bin/pkill /usr/bin/pkill /bin/ps /usr/bin/ps

COPY flag.txt .

COPY redis.conf /etc/redis/redis.conf

ADD supervisord.conf /etc/supervisor/conf.d/supervisord.conf

ENTRYPOINT ["/usr/bin/supervisord"]
