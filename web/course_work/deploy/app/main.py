import jwt
from fastapi import FastAPI, Request, Response, HTTPException, Depends
from pydantic import BaseModel
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from app.db import database, User
from app.config import settings


class Auth(BaseModel):
    username: str
    password: str


class RedirectMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        if response.status_code == 401:
            return RedirectResponse(url='/logout')
        return response


def get_current_user_from_cookie(request: Request, response: Response):
    token = request.cookies.get("session")
    if not token:
        raise HTTPException(status_code=401, detail="Missing JWT token")

    try:
        header = jwt.get_unverified_header(token)
        if header.get("alg") == "none":
            payload = jwt.decode(token, options={"verify_signature": False})
        else:
            payload = jwt.decode(token, settings.secret_key, algorithms=['HS256'])
        return payload
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        response.delete_cookie(key="session")
        raise HTTPException(status_code=401, detail="Invalid or expired JWT token")


def create_signed_cookie(data: dict) -> str:
    return jwt.encode(data, settings.secret_key, algorithm='HS256')


app = FastAPI(
    docs_url=None,
    redoc_url=None,
    openapi_url=None
)

app.add_middleware(RedirectMiddleware)

templates = Jinja2Templates(directory='templates')


@app.on_event('startup')
async def startup():
    if not database.is_connected:
        await database.connect()


@app.on_event('shutdown')
async def shutdown():
    if database.is_connected:
        await database.disconnect()


@app.get('/')
async def root(request: Request, current_user: dict = Depends(get_current_user_from_cookie)):
    message = f'Hello, {current_user.get("username")}!'
    return templates.TemplateResponse(request, 'index.html', {'message': message})


@app.post('/auth/register')
async def register(response: Response, auth: Auth):
    if await User.objects.get_or_none(username=auth.username) is not None:
        raise HTTPException(status_code=400, detail='Username already registered')

    user = User(username=auth.username, password=auth.password)
    await user.save()

    cookie_data = {
        'username': auth.username
    }

    token = create_signed_cookie(cookie_data)

    response.set_cookie(key="session", value=token, httponly=True, max_age=3600)

    return {"message": "User registered successfully"}


@app.post('/auth/login')
async def login(response: Response, auth: Auth):
    user = await User.objects.get_or_none(username=auth.username)

    if user is None or user.password != auth.password:
        raise HTTPException(status_code=404, detail='Incorrect username or password')

    cookie_data = {
        'username': auth.username
    }

    token = create_signed_cookie(cookie_data)

    response.set_cookie(key="session", value=token, httponly=True, max_age=3600)

    return {"message": "Logged in successfully"}


@app.get('/logout')
async def logout(response: Response):
    response = RedirectResponse(url='/login')
    response.delete_cookie(key="session")
    return response


@app.get('/login', response_class=HTMLResponse)
async def login_form(request: Request):
    return templates.TemplateResponse(request, 'login.html')


@app.get('/register', response_class=HTMLResponse)
async def login_form(request: Request):
    return templates.TemplateResponse(request, 'register.html')


@app.get('/admin', response_class=HTMLResponse)
async def admin(request: Request, current_user: dict = Depends(get_current_user_from_cookie)):
    if current_user.get("username") != "admin":
        return RedirectResponse(url='/login')
    return templates.TemplateResponse(request, 'admin.html', {'flag': settings.flag})
