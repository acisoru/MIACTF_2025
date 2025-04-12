# Mia_girlfriend | Medium | Reverse

## Информация

You've met a beautiful girl, whose name is Mia.
Are you brave enough to talk with her and get a flag?
Mia - [@MiaCTF_girlfriend_bot](https://t.me/MiaCTF_girlfriend_bot).  
Remember that you have to wait for 2 seconds between messages!

## Деплой

```
cd deploy
docker-compose up --build
```


## Выдать участинкам

[public/](public/)

## Описание

Телеграм-бот, который для проверки запускает бинари. Необходимо понять, в каком порядке и что отправить боту, чтобы получить флаг.

## Решение

[src/](src/)
В первый и третий раз нужно сказать комплименты. В первый раз - платье, в третий - макияж.  
Во второй раз надо рассказать историю "Never_gonna_give_you_up".  
В четвёртый раз нужно сходить в театр.  
В пятый раз надо подарить Мороженое или Шоколадку.


## Флаг

miactf{NevEr_g0nNa_1et_y0u_d0Wn}

