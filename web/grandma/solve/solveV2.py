from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/', methods=['GET'])
def headers():
    headers = dict(request.headers)
    print(headers)
    return "hello_header"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)