# Sus-tem | easy | admin

## Информация
> Кажется на этой подозрительной системе запущен какой-то подозрительный процесс, помоги узнать что он делает!
>  
> Задание не требует перебора флагов.
>  
> SSH: `ssh user@<ip> -p <port>`  
> Пароль: `password`

## Деплой
Разархивировать `scripts.zip` в `./deploy/scripts`  
В `docker-compose.yml` указать желаемый порт (по умолчанию `13401`)
```sh
cd deploy
docker compose up -d --build
```

## Выдать участникам
- `ssh user@<ip> -p <port>`
- password: `password`

## Описание
`ps aux` чтобы увидеть запущенный процесс на сервере, повышение привилегий через `sudo strace`

## Решение
Зайдя на ssh по выданным кредам, увидим странную систему. 

```
Warning: Your server got hacked! Try to find the real flag! You'll NEVER find it!
SUS-TEM>
```

В `~` увидим много папок с sh-скриптами одинакового содержания
```sh
#!/bin/sh
while true; do
    echo "miactf{GRFrZvikuljeqpr8}"
    sleep 1
    echo "Running system check..."
    sleep 1
    echo "System task completed."
    sleep 1
done
```
в которых будет отличатся только рандомно-сгенерированный флаг, который является фейковым.

Нам надо как-то найти скрипт который выделяется относительно других, или, судя по описанию таска, скрипт который сейчас запущен на сервере и должен выводить флаг.

Чтобы посмотреть запущенные на сервере процессы существует команда `ps`.

```sh
SUS-TEM> ps 
PID   USER     TIME  COMMAND
    1 root      0:00 sshd: /usr/sbin/sshd -D -e [listener] 0 of 1000-1000 startups
    7 root      5:29 {.service-restar} /bin/sh /home/user/folder_13/subfolder_18/.service-restart_1866.sh
513676 root      0:00 sshd-session: user [priv]
513683 user      0:00 sshd-session: user@pts/0
513684 user      0:00 -sh
514345 root      0:00 sleep 1
514346 user      0:00 ps aux
```

Мы видим, что в `folder_13/subfolder_18/` запущен скрипт `.service-restart_1866.sh`, попробуем прочитать его.

```sh
SUS-TEM> cat ./folder_13/subfolder_18/.service-restart_1866.sh
cat: can't open './folder_13/subfolder_18/.service-restart_1866.sh': Permission denied
```

Хм, файл не открывается, посмотрим права доступа к этому файлу

```sh
SUS-TEM> ls -l ./folder_13/subfolder_18/.service-restart_1866.sh
-rwx------    1 root     root           171 Mar 19 19:32 ./folder_13/subfolder_18/.service-restart_1866.sh
```

Похоже доступ к этому файлу имеет только root, а следовательно нам надо будет повысить свои привилегии. 

Попробуем сделать это как на своей домашней системе: `sudo cat ./folder_13/subfolder_18/.service-restart_1866.sh`

```sh
SUS-TEM> sudo cat ./folder_13/subfolder_18/.service-restart_1866.sh
[sudo] password for user:
Sorry, user user is not allowed to execute '/bin/cat ./folder_13/subfolder_18/.service-restart_1866.sh' as root on 6cd2f715115b.
```

Хмм, введя пароль `password` из выданных кредов нам говорится, что мы не можем исполнять `cat` как `root`.

Но это значит что возможно что-то мы мы можем исполнять как `root`, как узнать что?

прописав `sudo -h` найдем нужную нам команду:

```sh
  -l, --list                    list user's privileges or check a specific
                                command; use twice for longer format
```

Пропишем:

```sh
SUS-TEM> sudo -l
Matching Defaults entries for user on 6cd2f715115b:
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

Runas and Command-specific defaults for user:
    Defaults!/usr/sbin/visudo env_keep+="SUDO_EDITOR EDITOR VISUAL"

User user may run the following commands on 6cd2f715115b:
    (ALL) NOPASSWD: /usr/bin/strace
```

Видим что у команды strace установлен флаг `NOPASSWD`, это значит что мы можем вызвать ее через `sudo` за `user`.

Через strace можно прочитать что сейчас делает запущенный процесс по `pid` процесса или по имени исполняемого файла.

```sh
SUS-TEM> sudo strace ./folder_13/subfolder_18/.service-restart_1866.sh
execve("./folder_13/subfolder_18/.service-restart_1866.sh", ["./folder_13/subfolder_18/.servic"...], 0x7ffeb7b44f00 /* 15 vars */) = 0
...
read(10, "#!/bin/sh\nwhile true; do\n    ech"..., 2047) = 171
write(1, "miactf{5ud0_5tr4c3_fl4g}\n", 25miactf{5ud0_5tr4c3_fl4g}
) = 25
stat("/usr/local/sbin/sleep", 0x7ffec758bb50) = -1 ENOENT (No such file or directory)
...
write(1, "Running system check...\n", 24Running system check...
```

Увидим в логах уже нужный нам, правильный флаг.

## Флаг
`miactf{5ud0_5tr4c3_fl4g}`