from fastapi import FastAPI
from collections import defaultdict

from starlette.types import Message

app = FastAPI(
    title="Emilia Hiring Challenge 👩‍💻",
    description="Help Emilia 👩 to fix our tests and get a job interview 💼🎙️!",
)


"""
Task 1 - Warmup
"""

def missing_language_message(language: str) -> str:
    return f"Sorry, we do not support {language} language yet."

@app.get("/task1/greet/{name}", tags=["Task 1"], summary="👋🇩🇪🇬🇧🇪🇸")
async def task1_greet(name: str, language: str = "de") -> str:
    """Greet somebody in German, English or Spanish!"""
    # Write your code below
    greetings = {
        "de": f"Hallo {name}, ich bin Emilia.",
        "en": f"Hello {name}, I am Emilia.",
        "es": f"Hola {name}, soy Emilia.",
        "ita": f"Hallo {name}, leider spreche ich nicht '{language}'!"
    }
    greetings = defaultdict(lambda: missing_language_message(language), greetings)
    return greetings[language]


"""
Task 2 - snake_case to cameCase
"""

import re
from re import Match
from typing import Any, Callable


def capitalize_letter(match: Match) -> str:
    """
        Captures and capitalizes the first letter after every
        underscore character matched in the camelize() function.
    """
    return match.group(1).upper()

def camelize(key: str) -> str:
    """Takes string in snake_case format returns camelCase formatted version."""
    # Write your code below
    return re.sub(r"\_(\w)", capitalize_letter, key)


@app.post("/task2/camelize", tags=["Task 2"], summary="🐍➡️🐪")
async def task2_camelize(data: dict[str, Any]) -> dict[str, Any]:
    """Takes a JSON object and transfroms all keys from snake_case to camelCase."""
    return {camelize(key): value for key, value in data.items()}


"""
Task 3 - Handle User Actions
"""
import string
from functools import wraps
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


def does_user_exist(function: Callable[[ActionRequest], ActionResponse]
                    ) -> Callable[[ActionRequest], ActionResponse]:
    @wraps(function)
    def wrapper(*args,**kwargs):
        user = kwargs.get("request").username
        try:
            friends[user]
        except KeyError:
            return ActionResponse(message=f"Hi {user}, I don't know you yet. But I would love to meet you!")
        return function(*args, **kwargs)
    return wrapper


def handle_call_action(request: ActionRequest) -> ActionResponse:
    # Write your code below
    user = request.username
    mapping = request.action.maketrans(dict.fromkeys(string.punctuation))
    unpunctual_action = request.action.translate(mapping)
    friend_match = set(unpunctual_action.split()).intersection(friends[request.username])
    if friend_match:
        return ActionResponse(message=f"🤙 Calling {friend_match.pop()} ...")
    return ActionResponse(message=f"{user}, I can't find this person in your contacts.")


def handle_reminder_action(_: ActionRequest) -> ActionResponse:
    # Write your code below
    return ActionResponse(message="🔔 Alright, I will remind you!")


def handle_timer_action(_: ActionRequest) -> ActionResponse:
    # Write your code below
    return ActionResponse(message="⏰ Alright, the timer is set!")


def handle_unknown_action(_: ActionRequest) -> ActionResponse:
    # Write your code below
    return ActionResponse(message="👀 Sorry , but I can't help with that!")


@app.post("/task3/action", tags=["Task 3"], summary="🤌")
@does_user_exist
def task3_action(request: ActionRequest) -> ActionResponse:
    """Accepts an action request, recognizes its intent and forwards it to the corresponding action handler."""
    # tip: you have to use the response model above and also might change the signature
    #      of the action handlers
    # Write your code below
    handler = {
            "call": handle_call_action,
            "remind": handle_reminder_action,
            "timer": handle_timer_action,
    }
    handler = defaultdict(lambda: handle_unknown_action, handler)
    action_type = set(request.action.lower().split()).intersection(handler.keys())
    return handler[action_type.pop() if action_type else False](request)


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
async def login(form_data: OAuth2PasswordRequestForm = Depends()) -> dict[str, str]:
    """Allows registered users to obtain a bearer token."""
    # fixme 🔨, at the moment we allow everybody to obtain a token
    # this is probably not very secure 🛡️ ...
    # tip: check the verify_password above
    # Write your code below
    user, password = get_user(form_data.username), form_data.password
    status_check = verify_password(password, user.hashed_password) if user else False
    if not all([user, status_check]):
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    payload = {
        "sub": form_data.username,
        "exp": datetime.utcnow() + timedelta(minutes=30),
    }
    return {
        "access_token": encode_jwt(payload),
        "token_type": "bearer",
    }


def get_user(username: str) -> Optional[User]:
    if username not in fake_users_db:
        return
    return User(**fake_users_db[username])


async def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid authentication credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    # check if the token 🪙 is valid and return a user as specified by the tokens payload
    # otherwise raise the credentials_exception above
    # Write your code below
    try:
        payload = decode_jwt(token)
        username = payload.get("sub")
        if not username:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    return get_user(username)



@app.get("/task4/users/{username}/secret", summary="🤫", tags=["Task 4"])
async def read_user_secret(
    username: str, current_user: User = Depends(get_current_user)
) -> str:
    """Read a user's secret."""
    # uppps 🤭 maybe we should check if the requested secret actually belongs to the user
    # Write your code below
    if current_user == get_user(username):
        return current_user.secret
    raise HTTPException(status_code=403, detail="Don't spy on other user!")

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
