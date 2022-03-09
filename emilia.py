from fastapi import FastAPI
from typing import Optional
import re

app = FastAPI(
    title="Emilia Hiring Challenge 👩‍💻",
    description="Help Emilia 👩 to fix our tests and get a job interview 💼🎙️!",
)


"""
Task 1 - Warmup
"""
translations = {
    "de": "Hallo {}, ich bin Emilia.",
    "en": "Hello {}, I am Emilia.",
    "es": "Hola {}, soy Emilia.",
}

@app.get("/task1/greet/{name}", tags=["Task 1"], summary="👋🇩🇪🇬🇧🇪🇸")
async def task1_greet(name: str, language: Optional[str] = 'de') -> str:
    """
    Greet somebody in German, English or Spanish!
    de is the default language If any other known lang parampeter is passed,
    we look up the translation else we state that we do not know lang xy in German
    """
    if language in translations.keys():
        return translations[language].format(name)
    return f"Hallo {name}, leider spreche ich nicht '{language}'!"


"""
Task 2 - snake_case to cameCase
"""

from typing import Any


def camelize(key: str):
    """Takes string in snake_case format returns camelCase formatted version."""
    constituents = key.split('_')
    return constituents[0] + ''.join(c.title() for c in constituents[1:])


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

intents = {
    "callContact": "call",
    "setReminder": "remind",
    "setTimer": "timer"
}

class ActionRequest(BaseModel):
    username: str
    action: str


class ActionResponse(BaseModel):
    message: str


def handle_call_action(request: ActionRequest) -> ActionResponse:
    for contact in friends[request.username]:
        if contact in request.action:
            return ActionResponse(message = f"🤙 Calling {contact} ...")

    return ActionResponse(message = f"{request.username}, I can't find this person in your contacts.")


def handle_reminder_action(request: ActionRequest) -> ActionResponse:
    return ActionResponse(message = "🔔 Alright, I will remind you!")


def handle_timer_action(request: ActionRequest) -> ActionResponse:
    return ActionResponse(message = "⏰ Alright, the timer is set!")


def handle_unknown_action(request: ActionRequest) -> ActionResponse:
    return ActionResponse(message = "👀 Sorry , but I can't help with that!")

cases = {
    "callContact": handle_call_action,
    "setReminder": handle_reminder_action,
    "setTimer": handle_timer_action
}

@app.post("/task3/action", tags=["Task 3"], summary="🤌")
def task3_action(request: ActionRequest):
    """
    We use a pretty silly and dumb rule-based system. Also this does not account for Emilia being multilingual. Obviously, fancy implementations would benefit a lot from
    retrieval based and probalistic approaches making use of standard NLP techniques, NER (especially for the request.action) and modeling of enriched
    training data (instead of silly string matching) :)
    """
    if request.username in friends.keys():
        for intent,trigger in intents.items():
            if trigger in request.action.lower():
                return cases[intent](request)
        return handle_unknown_action(request)
    else:
        return ActionResponse(message = f"Hi {request.username}, I don't know you yet. But I would love to meet you!")



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

# Docs at https://fastapi.tiangolo.com/tutorial/security/simple-oauth2/ have a vanilla example :)
@app.post("/task4/token", response_model=Token, summary="🔒", tags=["Task 4"])
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """Allows registered users to obtain a bearer token."""
    userDict = fake_users_db.get(form_data.username)
    if not userDict:
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    if not verify_password(form_data.password, fake_users_db[form_data.username]["hashed_password"]):
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
    return User(**fake_users_db[username])

# Check jwt.io
async def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid authentication credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    subject = decode_jwt(token)["sub"]
    if not subject:
        raise credentials_exception
    return User(**fake_users_db[subject])


@app.get("/task4/users/{username}/secret", summary="🤫", tags=["Task 4"])
async def read_user_secret(
    username: str, current_user: User = Depends(get_current_user)
):
    """Read a user's secret."""
    if current_user == get_user(username):
        return current_user.secret
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
for i in 1, 2, 3, 4:
    task = messages[f"task{i}"]
    info = partial(identity, task["info"])
    help_ = partial(identity, task["help"])
    tags = [f"Task {i}"]
    app.get(f"/task{i}", summary="📝", description=info(), tags=tags)(info)
    app.get(f"/task{i}/help", summary="🙋", description=help_(), tags=tags)(help_)
