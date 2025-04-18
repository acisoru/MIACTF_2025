# AES web token

## Сложность
medium

## Информация
> Почему бы не воспользоваться Advanced Encryption Standard для токенов?
>
> nc <ip>:6190

## Деплой
```sh
cd deploy
docker-compose up --build -d
```

## Выдать участинкам
Архив из директории [public/](public/) и IP:PORT сервера

## Описание
AES CBC abuse/bit-flipping.

## Решение
Из-за неправильной логики приложения в ошибке выводится не токен, а его расшированная версия. Рассмотрим, как работает CBC режим: \
Закрытый текст разбивается на блоки: пусть это `ct[0], ct[1], ..., ct[n - 1], ct[n]` \
Тогда расшифровка `pt` будет выглядеть так: (`sea` - расшифровка блока `aes`) \
```
pt[0] = sea(ct[0]) ^ iv
pt[1] = sea(ct[1]) ^ ct[0]
...
pt[n - 1] = sea(ct[n - 1]) ^ ct[n - 2]
pt[n] = sea(ct[n]) ^ ct[n - 1]
```
Пусть мы хотим, чтобы блоки были некоторыми `tok[0], tok[1], ...`\
Возьмем для начала `ct` и `iv` из нулей, тогда в `pt[n]` будет `sea(ct[n])`.\
Если задать `ct[n - 1] = sea(ct[n]) ^ tok[n]`, то в `pt[n]` будет `tok[n]` - один блок уже такой, как надо. \
В `pt[n - 1]` будет `sea(ct[n - 1])`. Зададим `ct[n - 2] = sea(ct[n - 1]) ^ tok[n - 1]`, в `pt[n]` будет `tok[n]`, и так далее для каждого блока (для первого блока надо будет подменить `iv` вместо `ct[-1]`). \
Так получается рабочий токен. Получаем флаг.

Эксплоит: [solve.py](solve/solve.py).

## Флаг
`miactf{p1s_d0n7_us3_AES_f0r_0th3r_purp0s3s_w1th0ut_th1nk1ng}`

