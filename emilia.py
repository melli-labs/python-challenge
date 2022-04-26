from tomlkit.api import parse
from pathlib import Path
from passlib.context import CryptContext
from jose import JWTError, jwt
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi import Depends, HTTPException, status
from typing import Optional
from functools import partial
from datetime import datetime, timedelta
from pydantic import BaseModel
from typing import Any
from fastapi import FastAPI
import re

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
    message = {
        "de": f"Hallo {name}, ich bin Emilia.",
        "en": f"Hello {name}, I am Emilia.",
        "es": f"Hola {name}, soy Emilia."
    }
    return message.get(language, f"Hallo {name}, leider spreche ich nicht '{language}'!")


"""
Task 2 - snake_case to cameCase
"""


def camelize(key: str):
    """Takes string in snake_case format returns camelCase formatted version."""

    # Split the keys by underscore.
    components = key.split('_')

    # We capitalize the first letter of each component except the first one
    # with the 'title' method and join them together.
    return components[0] + ''.join(x.title() for x in components[1:])


@app.post("/task2/camelize", tags=["Task 2"], summary="🐍➡️🐪")
async def task2_camelize(data: dict[str, Any]) -> dict[str, Any]:
    """Takes a JSON object and transfroms all keys from snake_case to camelCase."""
    return {camelize(key): value for key, value in data.items()}


"""
Task 3 - Handle User Actions
"""


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
    # check friend is exist on the friend list or not
    friend_found = [friend for friend in friends[request.username] if re.search(
        r'\b' + friend + r'\b', request.action, re.IGNORECASE)]

    if len(friend_found) > 0:
        return f"🤙 Calling {friend_found[0]} ..."
    else:
        return f"{request.username}, I can't find this person in your contacts."


def handle_reminder_action():
    return "🔔 Alright, I will remind you!"

def handle_timer_action():
    return "⏰ Alright, the timer is set!"

def handle_unknown_action():
    return "👀 Sorry , but I can't help with that!"

def handle_unknown_user_action(username: str):
    return f"Hi {username}, I don't know you yet. But I would love to meet you!"

def handler(request: ActionRequest):

    message = ""

    if request.username not in friends:  # Check if the user is exist on the dict.
        message = handle_unknown_user_action(request.username)

    elif re.search(r'\bcall\b', request.action, re.IGNORECASE):  # Check if its an Call action
        message = handle_call_action(request)

    elif re.search(r'\bremind\b', request.action, re.IGNORECASE):  # Check if its an remind action
        message = handle_reminder_action()

    elif re.search(r'\btimer\b', request.action, re.IGNORECASE):  # Check if its an timer action
        message = handle_timer_action()

    else:  # If none of the above action exist, call unknown action.
        message = handle_unknown_action()

    return {'message': message}


@app.post("/task3/action", response_model=ActionResponse, tags=["Task 3"], summary="🤌")
def task3_action(request: ActionRequest):
    """Accepts an action request, recognizes its intent and forwards it to the corresponding action handler."""
    return handler(request)


"""
Task 4 - Security
"""


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

    # Check if the user is exist.
    if not (user := get_user(form_data.username)):
        raise unauthorize("Incorrect username or password")

    # Verify password
    if not verify_password(form_data.password, user.hashed_password):
        raise unauthorize("Incorrect username or password")

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


def unauthorize(detail: str, code: Optional[int] = status.HTTP_401_UNAUTHORIZED):
    return HTTPException(
        status_code=code,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


async def get_current_user(token: str = Depends(oauth2_scheme)) -> User:

    try:
        payload = decode_jwt(token)

        # check if the token 🪙 is valid
        if payload['exp'] < int(datetime.now().timestamp()):
            raise Exception("Token expires")
    except:
        # otherwise raise the credentials_exception
        raise unauthorize("Invalid authentication credentials")

    return get_user(payload['sub'])


@app.get("/task4/users/{username}/secret", summary="🤫", tags=["Task 4"])
async def read_user_secret(
    username: str, current_user: User = Depends(get_current_user)
):
    """Read a user's secret."""
    # uppps 🤭 maybe we should check if the requested secret actually belongs to the user
    if username != current_user.username:
        raise unauthorize("Don't spy on other user!", status.HTTP_403_FORBIDDEN)

    if user := get_user(username):
        return user.secret


"""
Task and Help Routes
"""


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
