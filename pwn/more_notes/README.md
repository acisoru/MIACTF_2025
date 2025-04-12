# MORE_NOTES | MEDIUM | PWN

## Информация

> Самый обычный сервис, в котором можно оставлять записки
>
> nc <ip>:37373

## Деплой

```sh
cd deploy
docker-compose up --build -d
```

## Выдать участинкам

Архив из директории [public/](public/) и IP:PORT сервера

## Описание

Проэксплуатировать уязвимость связанную с осбождением памяти и записать ROP цепочки на стек

## Решение

[Эксплоит](solve/exploit.py)

## Флаг

`miactf{SO_YOU_kn0w_H0w_tcAcHE_w0rkS_cOOl}`

