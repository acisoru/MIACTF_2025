#!/bin/bash

# Показываем баннер перед вводом команды
bash /etc/banner.sh

# Запрос команды
read -p "# " command

# Преобразуем команду в нижний регистр
lower_command=$(echo "$command" | tr '[:upper:]' '[:lower:]')

# Разрешаем команды с 'for' и 'grep', чтобы избежать блокировки циклов
if [[ "$lower_command" == for*grep* ]]; then
    eval "$command"
    exit 0
fi

# Блокируем спецсимволы, которые могут использоваться для обхода
if [[ "$lower_command" =~ [\`\$\(\)\|\&\;\>\<] ]]; then
    echo "Disallowed symbols detected!"
    exit 1
fi

# Читаем список запрещённых команд из файла и проверяем, содержится ли какая-либо из них в команде
for forbidden in $(cat /etc/forbidden.txt); do
    if [[ "$lower_command" == *"$forbidden"* ]]; then
        echo "Disallowed command detected: $forbidden"
        exit 1
    fi
done

# Запрещаем ввод в обход через stdin
if [ ! -t 0 ]; then
    echo "Direct input is not allowed!"
    exit 1
fi


# Выполняем команду
eval "$command"

# Закрываем сессию
exit 0
