from fastapi import FastAPI, Query

app = FastAPI(
    title="Melli Hiring Challenge 👩‍💻",
    description="Help Melli 👩 to fix our tests and get a job interview 💼🎙️!",
)


"""
Task 1 - Warmup
"""


@app.get("/task1/greet/{name}", tags=["Task 1"], summary="👋🇩🇪🇬🇧🇪🇸")
async def task1_greet(
    name: str,
    language: str = Query("de"),
) -> str:
    """Greet somebody in German, English or Spanish!"""

    greetings = {
        "en": f"Hello {name}, I am Melli.",
        "de": f"Hallo {name}, ich bin Melli.",
        "es": f"Hola {name}, soy Melli.",
    }

    if language in greetings:
        return greetings[language]
    else:
        return f"Hallo Ben, leider spreche ich nicht '{language}'!"


"""
Task 2 - snake_case to cameCase
"""

from typing import Any


def camelize(key: str):
    """Takes string in snake_case format returns camelCase formatted version."""
    components = key.split("_")
    return components[0] + "".join(x.title() for x in components[1:])


@app.post("/task2/camelize", tags=["Task 2"], summary="🐍➡️🐪")
async def task2_camelize(data: dict[str, Any]) -> dict[str, Any]:
    """Takes a JSON object and transfroms all keys from snake_case to camelCase."""
    return {camelize(key): value for key, value in data.items()}


"""
Task 3 - Handle User Actions
"""

from pydantic import BaseModel
import spacy

nlp = spacy.load("en_core_web_sm")

friends = {
    "Matthias": {"Sahar", "Franziska", "Hans"},
    "Stefan": {"Felix", "Ben", "Philip"},
}

intent_mapping = {
    "call": ["call"],
    "reminder": ["remind", "remember"],
    "timer": ["timer"],
    "unknown": [],
}


class ActionRequest(BaseModel):
    username: str
    action: str


class ActionResponse(BaseModel):
    message: str


def identify_intent(action_text):
    action_text = action_text.lower()
    for intent, keywords in intent_mapping.items():
        if any(keyword in action_text for keyword in keywords):
            return intent
    return "unknown"


def extract_call_name(action_text, friends_list):
    doc = nlp(action_text)
    for token in doc:
        lowercase_token = token.text.lower()
        if lowercase_token in (name.lower() for name in friends_list):
            return next(
                name for name in friends_list if name.lower() == lowercase_token
            )
    return ""


@app.post("/task3/action", tags=["Task 3"], summary="🤌")
def task3_action(request: ActionRequest):
    """Accepts an action request, recognizes its intent and forwards it to the corresponding action handler."""

    intent = identify_intent(request.action)
    action_taker = request.username

    if action_taker in friends.keys():
        if intent == "call":
            return handle_call_action(request.action, action_taker)
        elif intent == "reminder":
            return handle_reminder_action(request.action)
        elif intent == "timer":
            return handle_timer_action(request.action)
        else:
            return handle_unknown_action(request.action)
    else:
        return ActionResponse(
            message=f"Hi {action_taker}, I don't know you yet. But I would love to meet you!"
        )


def handle_call_action(action_text, action_taker):
    call_name = extract_call_name(action_text, friends[action_taker])
    if call_name:
        return ActionResponse(message=f"🤙 Calling {call_name} ...")
    else:
        return ActionResponse(
            message=f"{action_taker}, I can't find this person in your contacts."
        )


def handle_reminder_action(action_text):
    return ActionResponse(message="🔔 Alright, I will remind you!")


def handle_timer_action(action_text):
    return ActionResponse(message="⏰ Alright, the timer is set!")


def handle_unknown_action(action_text):
    return ActionResponse(message="👀 Sorry , but I can't help with that!")


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

    customer = form_data.username
    password = form_data.password

    if customer not in fake_users_db:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )

    bd_password = fake_users_db[customer]["hashed_password"]

    if not verify_password(password, bd_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )

    payload = {
        "sub": customer,
        "exp": datetime.utcnow() + timedelta(minutes=30),
    }

    return {
        "access_token": encode_jwt(payload),
        "token_type": "bearer",
    }


def get_user(username: str) -> Optional[User]:
    user_data = fake_users_db.get(username)
    if user_data:
        return User(**user_data)


async def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    decoded_token = decode_jwt(token)
    return get_user(decoded_token["sub"])


@app.get("/task4/users/{username}/secret", summary="🤫", tags=["Task 4"])
async def read_user_secret(
    username: str, current_user: User = Depends(get_current_user)
):
    """Read a user's secret."""
    user = get_user(username)

    if user is None:
        raise HTTPException(
            status_code=404,
            detail="User not found",
        )

    if user == current_user:
        return user.secret
    else:
        raise HTTPException(
            status_code=403,
            detail="Don't spy on other user!",
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
