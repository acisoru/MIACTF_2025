from flask import Flask, render_template, request, redirect, make_response, session
from os import getenv

app = Flask(__name__)
app.secret_key = "jfjdfksdjdfklasjdfdfasfSFQF"
flag = getenv('FLAG', 'flag{T3$t}')
AUTH_TOKEN = getenv('AUTH_TOKEN')  # Токен авторизации

users = {}

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in users:
            return "User already exists!"
        users[username] = password
        return redirect('/login')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in users and users[username] == password:
            session['username'] = username
            token = str(AUTH_TOKEN) if username == 'admin' else 'user_token'
            resp = make_response(redirect('/'))
            resp.set_cookie('session', token)
            return resp
        return "Invalid credentials!"
    return render_template('login.html')

@app.route('/logout', methods=['GET'])
def logout():
    # Удаляем пользователя из сессии
    session.pop('username', None)
    # Удаляем токен из cookies
    resp = make_response(redirect('/'))
    resp.set_cookie('session', '', expires=0)  # Устанавливаем истекший срок действия куки
    return resp

@app.route('/')
@app.route('/index')
def index():
    token = request.cookies.get('session')
    print(token)
    if token == str(AUTH_TOKEN): 
        return render_template('index.html', is_admin=True, authorized=True, flag=flag, mgs='а как вам хватило совести скамнуть бедную не знающию бабушку, стыд()')
    elif token:
        return render_template('index.html', authorized=True)
    else:
        return render_template('index.html', authorized=False)

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True)
