# AWESOME_ASM | EASY | PWN

## Информация

> Похоже кто-то оставил syscall открытым, но мы же не будем этим пользоваться... Так?
>
> nc <ip>:17171

## Деплой

```sh
cd deploy
docker-compose up --build -d
```

## Выдать участинкам

Архив из директории [public/](public/) и IP:PORT сервера

## Описание

Нужно правильно повзаимодействовать с регистрами чтобы вызвать execve(/bin/sh)

## Решение

[Эксплоит](solve/exploit.py)

## Флаг

`miactf{y3aP_7Ha7_w4S_7h@T_3ASy_a5M_N0t_tHa7_h4rd}`

