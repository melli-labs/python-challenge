from fastapi import FastAPI

app = FastAPI(
    title="Emilia Hiring Challenge 👩‍💻",
    description="Help Emilia 👩 to fix our tests and get a job interview 💼🎙️!",
)


"""
Task 1 - Warmup
"""


@app.get("/task1/greet/{name}", tags=["Task 1"], summary="👋🇩🇪🇬🇧🇪🇸")
async def task1_greet(name: str, language: str = 'de') -> str:
    """Greet somebody in German, English or Spanish!"""

    # define greetings dictionary
    greetings = {
        'de': f"Hallo {name}, ich bin Emilia.",
        'en': f"Hello {name}, I am Emilia.",
        'es': f"Hola {name}, soy Emilia."
    }

    if language in greetings:
        return greetings[language]
    else:
        return f"Hallo {name}, leider spreche ich nicht '{language}'!"


"""
Task 2 - snake_case to camelCase
"""

from typing import Any
import re


def camelize(key: str):
    """Takes string in snake_case, returns camelCase formatted version."""

    # Use regular expressions to replace all occurrences of '_x'
    return re.sub(r'_([a-z])', lambda x: x.group(1).upper(), key)


@app.post("/task2/camelize", tags=["Task 2"], summary="🐍➡️🐪")
async def task2_camelize(data: dict[str, Any]) -> dict[str, Any]:
    """
    Takes a JSON object and transforms all keys from snake_case
    to camelCase.
    """
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


def handle_call_action(username: str, action: str):

    # call friend
    for friend in friends[username]:
        if friend in action:
            return {'message': f"🤙 Calling {friend} ..."}

    # if friend is unknown
    return {'message': f"{username}, "
                       f"I can't find this person in your contacts."}


def handle_reminder_action(action: str):

    # action is not used here, of course there would be something to implement
    return {'message': "🔔 Alright, I will remind you!"}


def handle_timer_action(action: str):

    # action is not used here, of course there would be something to implement
    return {'message': "⏰ Alright, the timer is set!"}


def handle_unknown_action(action: str):

    # action is not used here, of course there would be something to implement
    return {'message': "👀 Sorry , but I can't help with that!"}


def handle_unknown_user(username: str):

    return {'message': f"Hi {username}, I don't know you yet. "
                       f"But I would love to meet you!"}


@app.post("/task3/action", tags=["Task 3"], summary="🤌")
def task3_action(request: ActionRequest):
    """
    Accepts an action request, recognizes its intent and forwards it to the
    corresponding action handler.
    """

    username = request.username
    action = request.action

    # unknown user
    if username not in friends:
        return handle_unknown_user(username)

    if 'call' in action.lower():
        return handle_call_action(username, action)
    elif 'remind' in action.lower():
        return handle_reminder_action(action)
    elif 'timer' in action.lower():
        return handle_timer_action(action)
    else:
        return handle_unknown_action(action)


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
ALGORITHM = "HS256"

encode_jwt = partial(jwt.encode, key=SECRET_KEY, algorithm=ALGORITHM)
decode_jwt = partial(jwt.decode, key=SECRET_KEY, algorithms=[ALGORITHM])

_crypt_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
verify_password = _crypt_context.verify
hash_password = _crypt_context.hash

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/task4/token")

fake_users_db = {
    "stefan": {
        "username": "stefan",
        "email": "stefan.buchkremer@meetap.de",
        "hashed_password": hash_password("decent-espresso-by-john-buckmann"),
        "secret": "I love pressure-profiled espresso ☕!",
    },
    "felix": {
        "username": "felix",
        "email": "felix.andreas@meetap.de",
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

    password = form_data.password
    username = form_data.username
    user = get_user(username)

    if user and verify_password(password, user.hashed_password):
        payload = {
            "sub": form_data.username,
            "exp": datetime.utcnow() + timedelta(minutes=30),
        }
        return {
            "access_token": encode_jwt(payload),
            "token_type": "bearer",
        }

    # in case of wrong credentials
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Incorrect username or password",
        headers={"WWW-Authenticate": "Bearer"},
    )
    raise credentials_exception


def get_user(username: str) -> Optional[User]:
    if username not in fake_users_db:
        return
    return User(**fake_users_db[username])


async def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    try:
        payload = decode_jwt(token)
    except jwt.ExpiredSignatureError:
        credentials_exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
        raise credentials_exception

    username = payload['sub']
    return get_user(username)


@app.get("/task4/users/{username}/secret", summary="🤫", tags=["Task 4"])
async def read_user_secret(
    username: str, current_user: User = Depends(get_current_user)
):
    """Read a user's secret."""
    user = get_user(username)

    if user and current_user and user == current_user:
        return user.secret
    else:
        credentials_exception = HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Don't spy on other user!",
            headers={"WWW-Authenticate": "Bearer"},
        )
        raise credentials_exception


"""
Task and Help Routes
"""

from functools import partial
from pathlib import Path

from tomlkit.api import parse

messages = parse((Path(__file__).parent / "messages.toml").read_text("utf-8"))


@app.get("/", summary="👋", tags=["Emilia"])
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
