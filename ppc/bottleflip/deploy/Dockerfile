FROM golang:1.23.5 AS builder

WORKDIR /app

COPY go.* .

RUN go mod download

COPY . .

RUN go build -o main ./main.go

FROM debian:bookworm-slim

WORKDIR /app
COPY --from=builder /app/main .

CMD ["./main"]