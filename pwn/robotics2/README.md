# ROBOTICS2 | HARD | PWN

## Информация

> Недавно в наследство от своего дедушки я получил завод, на производстве которого работают исключительно
> роботы! Говорят, что это самый технологичный и безопасный завод в мире...
> 
> nc <ip>:11331

## Деплой

```sh
cd deploy
docker-compose up --build -d
```

## Выдать участинкам

Архив из директории [public/](public/) и IP:PORT сервера

## Описание

Уязвимость в Use-After-Free, можем изменить fd у чанка в fastbins. Далее ликлесс пывн кучи и получение
шелла через собранную на куче файловую структуру

## Решение

[Эксплоит](solve/exploit.py)

## Флаг

`miactf{0nly_f4stb1ns_m4st3r_c4n_pwn_r0b0_f4c70ry}`
