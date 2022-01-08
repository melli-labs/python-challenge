from fastapi import FastAPI
from fastapi.responses import JSONResponse
from starlette import requests
from constants import (
    GREETINGS,
    INVALID_LANGUAGE_PARAM_ERROR,
    ERROR_MESSAGES,
    STOP_WORDS,
)
from typing import List, Optional
import re

app = FastAPI(
    title="Emilia Hiring Challenge 👩‍💻",
    description="Help Emilia 👩 to fix our tests and get a job interview 💼🎙️!",
)


"""
Task 1 - Warmup
"""


@app.get("/task1/greet/{name}", tags=["Task 1"], summary="👋🇩🇪🇬🇧🇪🇸")
async def task1_greet(name: str, language: Optional[str] = "de") -> str:
    """Greet somebody in German, English or Spanish!"""
    return GREETINGS.get(language.lower(), INVALID_LANGUAGE_PARAM_ERROR).format(
        name=name, selector=language
    )


"""
Task 2 - snake_case to cameCase
"""

from typing import Any


def camelize(key: str):
    """Takes string in snake_case format returns camelCase formatted version."""
    # Write your code below
    ""
    split = key.split("_")
    return f"{split[0]}{''.join([x.capitalize() for x in split[1:]])}"


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


def handle_parsing(function):
    def inner(*args, **kwargs):
        if args[1] not in friends:
            return {
                "message": f"Hi {args[1]}, I don't know you yet. But I would love to meet you!"
            }
        return {"message": function(*args, **kwargs)}

    return inner


def handle_call_action(action: List[str], usrename: str):
    # Write your code below

    for x in friends[usrename]:
        if x.casefold() in action:
            return f"🤙 Calling {x} ..."
    return f"{usrename}, I can't find this person in your contacts."


def handle_reminder_action(action: List[str]):
    """
    This funtion can also be extended to exatract the exact task
    for which the user wants to set a reminder.I have written a
    small code to demonstrade that
    """
    for index, string in enumerate(action):
        if string.casefold() == "to":
            print(f"Reminder set for {''.join(action[index+1:])}")
        break
    return "🔔 Alright, I will remind you!"


def handle_timer_action(action: List[str]):
    """
    This function can be extended to extarct the exact time
    for which the user wantes to set timer for. we can create a
    to_number function to parse strings to integar types and have
    have a dict containing time units, similar to the list shown below
    I have written a small peice of commented out code just to demonstarte that
    """
    index = None
    for i, x in enumerate(action):
        if x.casefold() in ["minutes", "second", "min", "sec"]:
            index = i
    print(action[index])

    return "⏰ Alright, the timer is set!"


def handle_unknown_action(action: str):
    # Write your code below
    return "👀 Sorry , but I can't help with that!"


@handle_parsing
def parse_intent(command: str, username: str):
    command = re.sub(r"[^\w]", " ", command).strip()
    tokenize = command.casefold().split(" ")
    command = [x for x in tokenize if x not in STOP_WORDS]
    """
    A better solution would ne to lemmatize and/or extract synonyms the words so that
    we can better extract the intent fo the user as below we are missing multiple cases
    for example `Ring Jared for me` we result in unknown command
    
    """
    if "call" in command:
        return handle_call_action(command, username)
    elif "timer" in command:
        return handle_timer_action(command)
    elif "reminder" in command or "remind" in command:
        return handle_reminder_action(command)
    else:
        return handle_unknown_action(command)


@app.post("/task3/action", tags=["Task 3"], summary="🤌", response_model=ActionResponse)
def task3_action(request: ActionRequest):
    return parse_intent(request.action, request.username)


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
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """Allows registered users to obtain a bearer token."""
    # fixme 🔨, at the moment we allow everybody to obtain a token
    # this is probably not very secure 🛡️ ...
    # tip: check the verify_password above
    # Write your code below
    ...

    user = get_user(form_data.username)
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(**ERROR_MESSAGES["INVALID_USER"])
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
        user = get_user(username)
        if username is None or not user:
            raise credentials_exception
        return user
    except JWTError:
        raise credentials_exception


@app.get("/task4/users/{username}/secret", summary="🤫", tags=["Task 4"])
async def read_user_secret(
    username: str, current_user: User = Depends(get_current_user)
):

    if not current_user:
        raise HTTPException(**ERROR_MESSAGES["INVALID_USER"])
    elif current_user.username != username:
        raise HTTPException(**ERROR_MESSAGES["UNAUTH_USER"])
    elif user := get_user(username):
        return user.secret


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
