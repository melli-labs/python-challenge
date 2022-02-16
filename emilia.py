from fastapi import FastAPI

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

    if language == "de":
        greeting = f"Hallo {name}, ich bin Emilia."
    elif language == "en":
        greeting = f"Hello {name}, I am Emilia."
    elif language == "es":
        greeting = f"Hola {name}, soy Emilia."
    else:
        greeting = f"Hallo {name}, leider spreche ich nicht '{language}'!"

    return greeting

"""
Task 2 - snake_case to cameCase
"""

from typing import Any


def camelize(key: str):
    """Takes string in snake_case format returns camelCase formatted version."""
    words = key.split('_')

    return words[0] + ''.join(word.capitalize() for word in words[1:])


@app.post("/task2/camelize", tags=["Task 2"], summary="🐍➡️🐪")
async def task2_camelize(data: dict[str, Any]) -> dict[str, Any]:
    """Takes a JSON object and transfroms all keys from snake_case to camelCase."""
    return {camelize(key): value for key, value in data.items()}


"""
Task 3 - Handle User Actions
"""

from pydantic import BaseModel
from transformers import pipeline

ner_classifier = pipeline("ner", model="dslim/bert-large-NER", grouped_entities=True, ignore_subwords=True)

friends = {
    "Matthias": ["Sahar", "Franziska", "Hans"],
    "Stefan": ["Felix", "Ben", "Philip"],
}


class ActionRequest(BaseModel):
    username: str
    action: str


class ActionResponse(BaseModel):
    message: str


def handle_call_action(request: ActionRequest):

    friend = None
    found_names = ner_classifier(request.action)
    for name in found_names:
        if 'PER' in name['entity_group'] and name['word'] in friends[request.username]:
            friend = name['word']

    if friend is None:
        return ActionResponse(message=f"{request.username}, I can't find this person in your contacts.")

    return ActionResponse(message=f"🤙 Calling {friend} ...")


def handle_reminder_action(request: ActionRequest):
    # Write your code below

    return ActionResponse(message="🔔 Alright, I will remind you!")


def handle_timer_action(request: ActionRequest):
    # Write your code below

    return ActionResponse(message="⏰ Alright, the timer is set!")


def handle_unknown_action(request: ActionRequest):

    return ActionResponse(message="👀 Sorry , but I can't help with that!")


@app.post("/task3/action", tags=["Task 3"], summary="🤌")
def task3_action(request: ActionRequest):
    """Accepts an action request, recognizes its intent and forwards it to the corresponding action handler."""

    if request.username not in friends:
        return ActionResponse(message=f"Hi {request.username}, I don't know you yet. But I would love to meet you!")

    possible_handlers = {
        'call': handle_call_action,
        'reminder': handle_reminder_action,
        'timer': handle_timer_action,
        'unknown': handle_unknown_action,
    }

    handler = possible_handlers['unknown']

    cur_request = ActionRequest(username=request.username, action=request.action)

    if "call" in cur_request.action.lower():
        handler = possible_handlers['call']
    if "timer" in cur_request.action.lower():
        handler = possible_handlers['timer']
    if ("remind" or "reminder") in cur_request.action.lower():
        handler = possible_handlers['reminder']

    return handler(cur_request)


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

    if form_data.username not in fake_users_db:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password")

    if not verify_password(form_data.password, fake_users_db[form_data.username]["hashed_password"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password")

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

    payload = decode_jwt(token)

    if datetime.utcfromtimestamp(payload['exp']) < datetime.utcnow():
        raise credentials_exception

    if user := get_user(payload['sub']):
        return user
    else:
        raise credentials_exception


@app.get("/task4/users/{username}/secret", summary="🤫", tags=["Task 4"])
async def read_user_secret(
    username: str, current_user: User = Depends(get_current_user)
):
    """Read a user's secret."""
    if user := get_user(username):
        if current_user == user:
            return user.secret
        else:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Don't spy on other user!")


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
