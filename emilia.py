from typing import Optional, Union

import uvicorn
from fastapi import FastAPI, Request

app = FastAPI(
    title="Emilia Hiring Challenge 👩‍💻",
    description="Help Emilia 👩 to fix our tests and get a job interview 💼🎙️!",
)


"""
Task 1 - Warmup
"""


@app.get("/task1/greet/{name}", tags=["Task 1"], summary="👋🇩🇪🇬🇧🇪🇸")
async def task1_greet(name: str, language: str = "de") -> str:
    """Greet somebody in German, English or Spanish!"""

    unknown_language_reply = f"Hallo {name}, leider spreche ich nicht '{language}'!"
    available_languages = {
        "de": f"Hallo {name}, ich bin Emilia.",
        "en": f"Hello {name}, I am Emilia.",
        "es": f"Hola {name}, soy Emilia.",
    }
    reply = (
        available_languages[language]
        if language in available_languages
        else unknown_language_reply
    )
    return reply


"""
Task 2 - snake_case to cameCase
"""

from typing import Any, Callable


def camelize(key: str) -> str:
    """Takes string in snake_case format returns camelCase formatted version."""
    split_key = key.split("_")
    first_item = split_key[0]
    camelized = first_item + "".join([item.lower().title() for item in split_key[1:]])
    return camelized


@app.post("/task2/camelize", tags=["Task 2"], summary="🐍➡️🐪")
async def task2_camelize(data: dict[str, Any]) -> dict[str, Any]:
    """Takes a JSON object and transfroms all keys from snake_case to camelCase."""
    return {camelize(key): value for key, value in data.items()}


"""
Task 3 - Handle User Actions
"""

import re

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


ActionHandler = Callable[[ActionRequest, Optional[str]], str]


def parse_action(request: ActionRequest) -> set[str]:
    match_pattern = r"\W+"
    parsed_instruction = set(
        [item.lower() for item in re.split(match_pattern, request.action) if item]
    )
    return parsed_instruction


def extract_instraction(
    parsed_instruction: set[str], keywords: set[str]
) -> Optional[str]:
    if instructon := keywords.intersection(parsed_instruction):
        return list(instructon)[0]


def extract_callee(
    known_user: bool,
    parsed_instructions: set[str],
    friends: dict[str, set[str]],
    username: str,
) -> Optional[str]:
    if known_user:
        if callee := friends[username].intersection(parsed_instructions):
            return list(callee)[0]


def execute_handler(
    known_user: bool,
    callee: Optional[str],
    request: ActionRequest,
    instruction: Optional[str],
) -> ActionResponse:
    if not known_user:
        return ActionResponse(
            message=f"Hi {request.username}, I don't know you yet. But I would love to meet you!"
        )

    handle_action: ActionHandler = get_action_handler_by_instruction(instruction)
    return ActionResponse(message=handle_action(request, callee))


def handle_call_action(request: ActionRequest, person_to_call: Optional[str]) -> str:
    if person_to_call:
        return f"🤙 Calling {person_to_call.title()} ..."
    else:
        return f"{request.username}, I can't find this person in your contacts."


def handle_reminder_action(_: ActionRequest, __: Optional[str]) -> str:
    return "🔔 Alright, I will remind you!"


def handle_timer_action(_: ActionRequest, __: Optional[str]) -> str:
    return "⏰ Alright, the timer is set!"


def handle_unknown_action(_: ActionRequest, __: Optional[str]) -> str:
    return "👀 Sorry , but I can't help with that!"


action_handler_by_instruction: dict[str, ActionHandler] = {
    "call": handle_call_action,
    "remind": handle_reminder_action,
    "timer": handle_timer_action,
}


def get_action_handler_by_instruction(instruction: Optional[str]) -> ActionHandler:
    return action_handler_by_instruction.get(instruction or "", handle_unknown_action)


@app.post("/task3/action", tags=["Task 3"], summary="🤌")
def task3_action(request: ActionRequest):
    """Accepts an action request, recognizes its intent and forwards it to the corresponding action handler."""

    keywords = set([item for item in action_handler_by_instruction])
    friends_set: dict[str, set[str]] = {
        k: set([name.lower() for name in v]) for k, v, in friends.items()
    }
    known_user = True if request.username in friends else False
    parsed_action: set[str] = parse_action(request)
    instruction: Optional[str] = extract_instraction(parsed_action, keywords)
    person_to_call: Optional[str] = extract_callee(
        known_user, parsed_action, friends_set, request.username
    )
    response: ActionResponse = execute_handler(
        known_user,
        person_to_call,
        request,
        instruction,
    )

    return response


"""
Task 4 - Security
"""

import time
from datetime import datetime, timedelta
from functools import partial
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import jwt
from jwt.exceptions import ExpiredSignatureError
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

    if form_data.username in fake_users_db:
        user: User = get_user(form_data.username)  # type: ignore
        if verify_password(form_data.password, user.hashed_password):
            payload = {
                "sub": form_data.username,
                "exp": datetime.utcnow() + timedelta(minutes=30),
            }
            return {
                "access_token": encode_jwt(payload),
                "token_type": "bearer",
            }
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Incorrect username or password",
    )


PayloadType = dict[str, Union[datetime, str]]


def get_user(username: str) -> Optional[User]:
    if username not in fake_users_db:
        return
    return User(**fake_users_db[username])


async def get_current_user(token: str = Depends(oauth2_scheme)) -> Optional[User]:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid authentication credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if decoded_token := decode_jwt_token(token):
        if user := get_user(decoded_token["sub"]):  # type: ignore
            return user
    raise credentials_exception


def decode_jwt_token(token: str) -> Optional[PayloadType]:
    try:
        decoded_token = decode_jwt(token)
        if decoded_token["exp"] >= time.time():
            return decoded_token
    except ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Signature has expired."
        )


@app.get("/task4/users/{username}/secret", summary="🤫", tags=["Task 4"])
async def read_user_secret(
    username: str, request: Request, current_user: User = Depends(get_current_user)
):
    """Read a user's secret."""
    requesting_user = get_user(username)
    if requesting_user and requesting_user.username != current_user.username:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Don't spy on other user!"
        )
    elif not requesting_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Hi {username}, I don't know you yet. But I would love to meet you!",
        )
    return requesting_user.secret


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
    info = partial(identity, task["info"])  # type: ignore
    help_ = partial(identity, task["help"])  # type: ignore
    tags = [f"Task {i}"]
    app.get(f"/task{i}", summary="📝", description=info(), tags=tags)(info)
    app.get(f"/task{i}/help", summary="🙋", description=help_(), tags=tags)(help_)


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
