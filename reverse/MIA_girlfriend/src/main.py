import telebot
import subprocess
import time
from telebot import types
from telebot.types import BotCommand

# Чтение токена
with open("api.txt", "r") as f:
    API_TOKEN = f.read().strip()

bot = telebot.TeleBot(API_TOKEN)
user_moods = {}
user_counts = {}
user_last_message_time = {}  # Хранение времени последнего сообщения

bot.set_my_commands([
    BotCommand("/start", "Начать общение с Мией"),
])

MESSAGE_COOLDOWN = 2

def is_on_cooldown(chat_id):
    last_time = user_last_message_time.get(chat_id, 0)
    return time.time() - last_time < MESSAGE_COOLDOWN

def update_last_message_time(chat_id):
    user_last_message_time[chat_id] = time.time()

@bot.message_handler(commands=['start'])
def start(message):
    update_last_message_time(message.chat.id)
    user_moods[message.chat.id] = True
    user_counts[message.chat.id] = 0

    user_name = message.from_user.first_name
    if message.from_user.last_name:
        user_name += " " + message.from_user.last_name

    greeting = f"Привет, {user_name}! Я Миа."
    bot.reply_to(message, greeting)

    markup = types.ReplyKeyboardMarkup(resize_keyboard=True)
    markup.add("Да", "Нет")

    bot.send_message(message.chat.id, "Познакомимся?", reply_markup=markup)

@bot.message_handler(func=lambda message: message.text in ["Да", "Нет"])
def handle_welcome(message):
    if is_on_cooldown(message.chat.id):
        return

    update_last_message_time(message.chat.id)
    mood = user_moods.get(message.chat.id, True)

    if not mood:
        bot.reply_to(message, "Я обиделась!")
    elif message.text == "Да":
        bot.reply_to(message, "Очень приятно")
        show_buttons(message)
    else:
        bot.reply_to(message, "Тогда пока.")
        user_moods[message.chat.id] = False

def show_buttons(message):
    markup = types.ReplyKeyboardMarkup(resize_keyboard=True)
    markup.add("Сделать комплимент", "Сделать подарок", "Сходить куда-нибудь", "Рассказать историю")
    bot.send_message(message.chat.id, "Что предложишь?", reply_markup=markup)

def show_compliments(message):
    markup = types.ReplyKeyboardMarkup(resize_keyboard=True)
    markup.add("Волосы", "Платье", "Глаза", "Макияж")
    bot.send_message(message.chat.id, "Что тебе нравится во мне?", reply_markup=markup)

def show_gifts(message):
    markup = types.ReplyKeyboardMarkup(resize_keyboard=True)
    markup.add("Шоколадка", "Мороженое", "Цветы", "Айфон")
    bot.send_message(message.chat.id, "Что подаришь?", reply_markup=markup)

def show_places(message):
    markup = types.ReplyKeyboardMarkup(resize_keyboard=True)
    markup.add("Кино", "Театр", "Погулять", "Ресторан")
    bot.send_message(message.chat.id, "Куда пойдём?", reply_markup=markup)

def show_history(message):
    bot.reply_to(message, "Я тебя внимательно слушаю:")

def safe_run_subprocess(binary_path, args):
    try:
        result = subprocess.run([binary_path] + args, capture_output=True, text=True, timeout=5)
        return result.returncode, result.stdout.strip()
    except (subprocess.SubprocessError, FileNotFoundError, TimeoutError) as e:
        return -1, "Ошибка при выполнении команды."

@bot.message_handler(func=lambda message: len(message.text) == 23)
def check_history(message):
    if is_on_cooldown(message.chat.id):
        return

    update_last_message_time(message.chat.id)
    mood = user_moods.get(message.chat.id, True)
    count = user_counts.get(message.chat.id, 0)

    if not mood:
        bot.reply_to(message, "Я обиделась!")
        return

    if count == 4:
        bot.reply_to(message, "Ты мне понравился")
        show_flag(message)
    else:
        ret, out = safe_run_subprocess("./check_history", [str(count), change_lang(message.text)])
        if ret == 1:
            user_moods[message.chat.id] = False
            user_counts[message.chat.id] = 0
        else:
            user_counts[message.chat.id] += 1
        bot.reply_to(message, out)
        show_buttons(message)

@bot.message_handler(func=lambda message: message.text in ["Сделать комплимент", "Сделать подарок", "Сходить куда-нибудь", "Рассказать историю"])
def handle_action(message):
    if is_on_cooldown(message.chat.id):
        return

    update_last_message_time(message.chat.id)
    mood = user_moods.get(message.chat.id, True)

    if not mood:
        bot.reply_to(message, "Я обиделась!")
        user_counts[message.chat.id] = 0
        show_buttons(message)
        return

    actions = {
        "Сделать комплимент": show_compliments,
        "Сделать подарок": show_gifts,
        "Сходить куда-нибудь": show_places,
        "Рассказать историю": show_history
    }

    actions[message.text](message)

def change_lang(s):
    words = {
        "Волосы": "Volosy", "Платье": "Platye", "Глаза": "Glaza", "Макияж": "Makyaz",
        "Кино": "Kino", "Театр": "Teatr", "Погулять": "Phogulat", "Ресторан": "Restoran"
    }
    return words.get(s, s)

@bot.message_handler(func=lambda message: message.text in ["Волосы", "Платье", "Глаза", "Макияж"])
def check_compliment(message):
    if is_on_cooldown(message.chat.id):
        return

    update_last_message_time(message.chat.id)
    handle_check(message, "./check_compliment")

@bot.message_handler(func=lambda message: message.text in ["Кино", "Театр", "Погулять", "Ресторан"])
def check_place(message):
    if is_on_cooldown(message.chat.id):
        return

    update_last_message_time(message.chat.id)
    handle_check(message, "./check_place")

def handle_check(message, binary_path):
    mood = user_moods.get(message.chat.id, True)
    count = user_counts.get(message.chat.id, 0)

    if not mood:
        bot.reply_to(message, "Я обиделась!")
        return

    if count == 4:
        bot.reply_to(message, "Ты мне понравился")
        show_flag(message)
    else:
        ret, out = safe_run_subprocess(binary_path, [str(count), change_lang(message.text)])
        if "Ya obidelas!" in out:
            user_moods[message.chat.id] = False
            user_counts[message.chat.id] = 0
        else:
            user_counts[message.chat.id] += 1
        bot.reply_to(message, out)
        show_buttons(message)

@bot.message_handler(func=lambda message: message.text in ["Шоколадка", "Мороженое", "Цветы", "Айфон"])
def check_gift(message):
    if is_on_cooldown(message.chat.id):
        return

    update_last_message_time(message.chat.id)
    mood = user_moods.get(message.chat.id, True)
    count = user_counts.get(message.chat.id, 0)

    if not mood:
        bot.reply_to(message, "Я обиделась!")
        user_counts[message.chat.id] = 0
        show_buttons(message)
        return

    if count == 4 and len(message.text) == 9:
        bot.reply_to(message, "Ты мне понравился")
        show_flag(message)
    else:
        bot.reply_to(message, "Мне такое не нравится!")

    user_moods[message.chat.id] = False
    user_counts[message.chat.id] = 0

@bot.message_handler(func=lambda message: True)
def handle_other_messages(message):
    if is_on_cooldown(message.chat.id):
        return

    update_last_message_time(message.chat.id)
    mood = user_moods.get(message.chat.id, True)
    if not mood:
        bot.reply_to(message, "Я обиделась!")
    else:
        bot.reply_to(message, "Я не понимаю, что ты имеешь в виду.")

def show_flag(message):
    try:
        with open("flag.txt", "r") as f:
            bot.send_message(message.chat.id, f"Держи флаг: {f.readline().strip()}")
    except Exception:
        bot.send_message(message.chat.id, "Флаг недоступен.")

bot.polling()
