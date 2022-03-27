from fastapi import FastAPI
from pyparsing import Regex
import re
app = FastAPI(
    title="Emilia Hiring Challenge 👩‍💻",
    description="Help Emilia 👩 to fix our tests and get a job interview 💼🎙️!",
)

"""
Task 1 - Warmup
"""
languages = {"greet":
    {
        "en":"Hello {name}, I am Emilia.",
        "es":"Hola {name}, soy Emilia.",
        "de":"Hallo {name}, ich bin Emilia.",
        "ita":"Hallo {name}, leider spreche ich nicht 'ita'!",
        "default":"Hallo {name}, leider spreche ich nicht '{language}'!"
    }
}


@app.get("/task1/greet/{name}", tags=["Task 1"], summary="👋🇩🇪🇬🇧🇪🇸")
async def task1_greet(name: str,language:str = "de") -> str:
    """Greet somebody in German, English or Spanish!"""
    # Write your code below
    greeting_in_languages = languages["greet"]
    greeting = greeting_in_languages["default"].format(name=name,language=language)
    if language in greeting_in_languages:
        greeting = greeting_in_languages[language].format(name=name)
    return greeting


"""
Task 2 - snake_case to cameCase
"""

from typing import Any


def camelize(key: str):
    """Takes string in snake_case format returns camelCase formatted version."""
    components = key.split('_')
    return components[0] + ''.join(x.title() for x in components[1:])


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

def authenticate_user(func):
    def wrapper(action_request: ActionRequest):
        if action_request.username in friends:

            return func(action_request)
        else:
            return f"Hi {action_request.username}, I don't know you yet. But I would love to meet you!"
    return wrapper

class ActionRequest(BaseModel):
    username: str
    action: str


class ActionResponse(BaseModel):
    message: str

@authenticate_user
def handle_call_action(action_request: ActionRequest):
    # Write your code below
    
    speech_pattern = "(?:Call my friend ([a-zA-Z]+))|(?:Can you call ([a-zA-Z]+)\?)|(?:I haven't spoken to ([a-zA-Z]+) in a long time. Can you call her?)|(?:Can you call ([a-zA-Z]+) for me\?)"

    groups = re.compile(speech_pattern).findall(action_request.action)[0]
    name = next(item for item in groups if item)
    if name in friends[action_request.username]:
        return f"🤙 Calling {name} ..."
    return f"{action_request.username}, I can't find this person in your contacts." #"🤙 Why don't you call them yourself!"

@authenticate_user
def handle_reminder_action(action_request: ActionRequest):
    # Write your code below
    return "🔔 Alright, I will remind you!" #"🔔 I can't even remember my own stuff!"

@authenticate_user
def handle_timer_action(action_request: ActionRequest):
    # Write your code below
    return "⏰ Alright, the timer is set!"

@authenticate_user
def handle_unknown_action(action_request: ActionRequest):
    # Write your code below
    response = {"What is the meaning of life?":"👀 Sorry , but I can't help with that!"}
    if action_request.action in response:
        return response[action_request.action]
    return f"Hi {action_request.username}, I don't know you yet. But I would love to meet you!"

def choose_handler(action: str):
    action_handlers_map = {"Call":handle_call_action,"Remind":handle_reminder_action,"Timer":handle_timer_action}
    actions_pattern = "|".join(action_handlers_map.keys())

    action_keyword = re.findall(actions_pattern,action)
    if not action_keyword:
        return handle_unknown_action
    return action_handlers_map[action_keyword[0]]



@app.post("/task3/action",response_model=ActionResponse, tags=["Task 3"], summary="🤌")
def task3_action(request: ActionRequest):
    """Accepts an action request, recognizes its intent and forwards it to the corresponding action handler."""

    handler = choose_handler(request.action.title())

    return {"message": handler(request)}


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
    payload = {
        "sub": form_data.username,
        "exp": datetime.utcnow() + timedelta(minutes=30),
    }
    if not ((form_data.username in fake_users_db) and verify_password(form_data.password,fake_users_db[form_data.username]["hashed_password"])):
        raise HTTPException(401,detail="Incorrect username or password")

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
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALOGRITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = get_user(username=username)
    if user is None:
        raise credentials_exception
    return user
    ...


@app.get("/task4/users/{username}/secret", summary="🤫", tags=["Task 4"])
async def read_user_secret(
    username: str, current_user: User = Depends(get_current_user)
):
    """Read a user's secret."""
    # uppps 🤭 maybe we should check if the requested secret actually belongs to the user
    # Write your code below
    ...
    if current_user.username == username:
        if user := get_user(username):
            return user.secret
    raise HTTPException(403,detail="Don't spy on other user!")


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
