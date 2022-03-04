from email import message
from fastapi import FastAPI
import re

app = FastAPI(
    title="Emilia Hiring Challenge 👩‍💻",
    description="Help Emilia 👩 to fix our tests and get a job interview 💼🎙️!",
)


"""
Task 1 - Warmup
"""


@app.get(
    "/task1/greet/{name}",
    tags=["Task 1"],
    summary="Greet somebody in German, English or Spanish!",
)
async def task1_greet(name: str, language: str = "de") -> str:
    """Greet somebody in German, English or Spanish!"""
    # Write your code below

    name = name.title()
    response_dict = {
        "de": f"Hallo {name}, ich bin Emilia.",
        "en": f"Hello {name}, I am Emilia.",
        "es": f"Hola {name}, soy Emilia.",
    }
    if language in response_dict.keys():
        return response_dict[language]
    else:
        return f"Hallo {name}, leider spreche ich nicht '{language}'!"


"""
Task 2 - snake_case to cameCase
"""

from typing import Any


def camelize(key: str) -> str:
    """Takes string in snake_case format returns camelCase formatted version.
       We use only build in functions.
    Args:
        key (str): a string with snake_case

    Returns:
        str: a camelCase string
    """
    camel_case = "".join(list(map(lambda x: x.title(), key.split("_"))))
    camel_case_with_first_lower = camel_case[0].lower() + camel_case[1:]
    return camel_case_with_first_lower


@app.post(
    "/task2/camelize",
    tags=["Task 2"],
    summary="Takes string in snake_case format returns camelCase formatted version.",
)
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


def __find_friend_in_action(action: str, username: str):
    return next((x for x in friends[username] if x in action), False)


def handle_call_action(action: str, username: str):
    friend = __find_friend_in_action(action, username)
    if friend:
        return f"🤙 Calling {friend} ..."
    else:
        return f"{username}, I can't find this person in your contacts."


def handle_reminder_action(action: str, username: str):
    return "🔔 Alright, I will remind you!"


def handle_timer_action(action: str, username: str):
    return "⏰ Alright, the timer is set!"


def handle_unknown_action():
    return "👀 Sorry , but I can't help with that!"


def handle_unknown_user(username: str):
    return f"Hi {username}, I don't know you yet. But I would love to meet you!"


@app.post(
    "/task3/action",
    tags=["Task 3"],
    summary="Accepts an action request, recognizes its intent and forwards it to the corresponding action handler.",
)
def task3_action(request: ActionRequest):
    """Accepts an action request, recognizes its intent and forwards it to the corresponding action handler."""
    handler = {
        "call": handle_call_action,
        "remind": handle_reminder_action,
        "timer": handle_timer_action,
        "unknown_action": handle_unknown_action,
        "unknown_user": handle_unknown_user,
    }

    match_action_list = re.findall(
        r"(call|remind|timer)", request.action, re.IGNORECASE
    )
    message = {}
    username = request.username.title()
    if match_action_list and username in friends:
        most_common = max(match_action_list, key=match_action_list.count)
        message["message"] = handler[most_common.lower()](request.action, username)
    elif not match_action_list:
        message["message"] = handler["unknown_action"]()
    else:
        message["message"] = handler["unknown_user"](username)

    return message


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


def get_user(username: str) -> Optional[User]:
    if username not in fake_users_db:
        return
    return User(**fake_users_db[username])


@app.post(
    "/task4/token",
    response_model=Token,
    summary="Allows registered users to obtain a bearer token.",
    tags=["Task 4"],
)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """Allows registered users to obtain a bearer token."""
    user = get_user(form_data.username)
    if user and verify_password(form_data.password, user.hashed_password):
        payload = {
            "sub": form_data.username,
            "exp": datetime.utcnow() + timedelta(minutes=30),
        }
        return {
            "access_token": encode_jwt(payload),
            "token_type": "bearer",
        }
    else:
        raise HTTPException(status_code=401, detail="Incorrect username or password")


async def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    # check if the token 🪙 is valid and return a user as specified by the tokens payload
    # otherwise raise the credentials_exception above
    # Write your code below
    payload = decode_jwt(token)
    if not None in (username := payload.get("sub"), payload.get("exp")):
        return get_user(username)
    else:
        raise HTTPException(status_code=401, detail="Invalid credentials!")


@app.get(
    "/task4/users/{username}/secret", summary="Read a user's secret.", tags=["Task 4"]
)
async def read_user_secret(
    username: str, current_user: User = Depends(get_current_user)
):
    """Read a user's secret."""
    user = get_user(username)
    if user and current_user == user:
        return user.secret
    else:
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
for i in range(1, 5):
    task = messages[f"task{i}"]
    info = partial(identity, task["info"])
    help_ = partial(identity, task["help"])
    tags = [f"Task {i}"]
    app.get(f"/task{i}", summary="📝", description=info(), tags=tags)(info)
    app.get(f"/task{i}/help", summary="🙋", description=help_(), tags=tags)(help_)
