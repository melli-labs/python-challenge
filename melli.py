from fastapi import FastAPI

app = FastAPI(
    title="Melli Hiring Challenge 👩‍💻",
    description="Help Melli 👩 to fix our tests and get a job interview 💼🎙️!",
)


"""
Task 1 - Warmup
"""


@app.get("/task1/greet/{name}", tags=["Task 1"], summary="👋🇩🇪🇬🇧🇪🇸")
async def task1_greet(name: str, language: str = None) -> str:
    """Greet somebody in German, English or Spanish!"""
    if language in ('de', None):
        return f'Hallo {name}, ich bin Melli.'

    if language == 'en':
        return f'Hello {name}, I am Melli.'

    if language == 'es':
        return f'Hola {name}, soy Melli.'

    return f'Hallo {name}, leider spreche ich nicht \'{language}\'!'


"""
Task 2 - snake_case to cameCase
"""

from typing import Any


def camelize(key: str):
    """Takes string in snake_case format returns camelCase formatted version."""
    head, *tail = key.split('_')
    titlecased = (part.title() for part in tail)
    parts = (head, *titlecased)
    return ''.join(parts)


@app.post("/task2/camelize", tags=["Task 2"], summary="🐍➡️🐪")
async def task2_camelize(data: dict[str, Any]) -> dict[str, Any]:
    """Takes a JSON object and transfroms all keys from snake_case to camelCase."""
    return {camelize(key): value for key, value in data.items()}


"""
Task 3 - Handle User Actions
"""

from pydantic import BaseModel

friends = {
    "Matthias": ["Sahar", "Franziska", "Hans"],
    "Stefan": ["Felix", "Ben", "Philip"],
}


class ActionRequest(BaseModel):
    username: str
    action: str


class ActionResponse(BaseModel):
    message: str


def handle_call_action(request: ActionRequest) -> ActionResponse:
    for friend in friends[request.username]:
      if friend in request.action:
        return ActionResponse(message=f'🤙 Calling {friend} ...')

    return ActionResponse(
        message=f'{request.username}, I can\'t find this person in your contacts.'
    )


def handle_reminder_action(_: ActionRequest) -> ActionResponse:
    return ActionResponse(message='🔔 Alright, I will remind you!')


def handle_timer_action(_: ActionRequest) -> ActionResponse:
    return ActionResponse(message='⏰ Alright, the timer is set!')


def handle_unknown_action(_: ActionRequest) -> ActionResponse:
    return ActionResponse(message='👀 Sorry , but I can\'t help with that!')


def handle_unknown_user(request: ActionRequest) -> ActionResponse:
    message = f'Hi {request.username}, I don\'t know you yet. But I would love to meet you!'
    return ActionResponse(message=message)


@app.post("/task3/action", tags=["Task 3"], summary="🤌")
def task3_action(request: ActionRequest):
    """Accepts an action request, recognizes its intent and forwards it to the corresponding action handler."""
    if request.username not in friends.keys():
      return handle_unknown_user(request)

    action = request.action.lower()

    if 'call' in action:
      return handle_call_action(request)

    if 'remind' in action:
      return handle_reminder_action(request)

    if 'timer' in action:
      return handle_timer_action(request)

    if 'call' in action:
      return handle_call_action(request)

    return handle_unknown_action(request)


"""
Task 4 - Security
"""

from datetime import datetime, timedelta
from functools import partial
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext

# create secret key with: openssl rand -hex 32
SECRET_KEY = "069d49a9c669ddc08f496352166b7b5d270ff64d3009fc297689aa8b0fb66d98"
ALOGRITHM = "HS256"

encode_jwt = partial(jwt.encode, key=SECRET_KEY, algorithm=ALOGRITHM)
decode_jwt = partial(jwt.decode, key=SECRET_KEY, algorithms=[ALOGRITHM])

_crypt_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
verify_password = _crypt_context.verify
hash_password = _crypt_context.hash

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/task4/token")

fake_users_db = {
    "stefan": {
        "username": "stefan",
        "email": "stefan.buchkremer@melli.com",
        "hashed_password": hash_password("decent-espresso-by-john-buckmann"),
        "secret": "I love pressure-profiled espresso ☕!",
    },
    "felix": {
        "username": "felix",
        "email": "felix.andreas@melli.com",
        "hashed_password": hash_password("elm>javascript"),
        "secret": "Rust 🦀 is the best programming language ever!",
    },
}


class User(BaseModel):
    username: str
    email: str
    hashed_password: str
    secret: str


class Token(BaseModel):
    access_token: str
    token_type: str


@app.post("/task4/token", response_model=Token, summary="🔒", tags=["Task 4"])
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """Allows registered users to obtain a bearer token."""
    is_user = lambda: form_data.username in fake_users_db

    is_authorized = lambda: verify_password(
        form_data.password,
        fake_users_db[form_data.username]['hashed_password']
    )

    access_token = lambda: encode_jwt(dict(
        sub=form_data.username,
        exp=datetime.utcnow() + timedelta(minutes=30)
    ))

    if is_user() and is_authorized():
        return dict(access_token=access_token(), token_type='bearer')

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail='Incorrect username or password',
    )


def get_user(username: str) -> Optional[User]:
    if username not in fake_users_db:
        return
    return User(**fake_users_db[username])


async def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    credentials_exception = lambda: HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail='Invalid authentication credentials',
        headers={'WWW-Authenticate': 'Bearer'},
    )

    user = decode_jwt(token)['sub']

    if user in fake_users_db:
        return get_user(user)

    raise credentials_exception()


@app.get("/task4/users/{username}/secret", summary="🤫", tags=["Task 4"])
async def read_user_secret(
    username: str, current_user: User = Depends(get_current_user)
):
    """Read a user's secret."""
    user = get_user(username)

    if user == current_user:
        return user.secret

    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail='Don\'t spy on other user!',
    )


"""
Task and Help Routes
"""

from functools import partial
from pathlib import Path

from tomlkit.api import parse

messages = parse((Path(__file__).parent / "messages.toml").read_text("utf-8"))


@app.get("/", summary="👋", tags=["Melli"])
async def hello():
    return messages["hello"]


identity = lambda x: x
for i in 1, 2, 3, 4:
    task = messages[f"task{i}"]
    info = partial(identity, task["info"])
    help_ = partial(identity, task["help"])
    tags = [f"Task {i}"]
    app.get(f"/task{i}", summary="📝", description=info(), tags=tags)(info)
    app.get(f"/task{i}/help", summary="🙋", description=help_(), tags=tags)(help_)
