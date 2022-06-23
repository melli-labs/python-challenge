from ast import Try
from email import message
from tomlkit import key
from fastapi import FastAPI

app = FastAPI(
    title="Emilia Hiring Challenge 👩‍💻",
    description="Help Emilia 👩 to fix our tests and get a job interview 💼🎙️!",
)


"""
Task 1 - Warmup
"""

DEFAULT_LANGUAGE = "de"
SUPPORTED_LANGUAGES = {"de","en","es"}


@app.get("/task1/greet/{name}", tags=["Task 1"], summary="👋🇩🇪🇬🇧🇪🇸")
async def task1_greet(name: str, language: str = DEFAULT_LANGUAGE) -> str:
    """Greet somebody in German, English or Spanish!"""
    # Write your code below

    default_greeting = f"Hallo {name}, leider spreche ich nicht '{language}'!"
    greetings = {"de": f"Hallo {name}, ich bin Emilia.", 
                 "en": f"Hello {name}, I am Emilia.",
                 "es": f"Hola {name}, soy Emilia."}
                 
    if language in SUPPORTED_LANGUAGES:
        return_greeting = greetings[language]
    else:
        return_greeting = default_greeting
    return return_greeting



"""
Task 2 - snake_case to cameCase
"""

from typing import Any


def camelize(key: str):
    """Takes string in snake_case format returns camelCase formatted version."""
    # Write your code below
    string_components = key.split("_")
    camelized_string = string_components[0]
    for component in string_components[1:]:
        camelized_string =''.join([camelized_string, component.capitalize()])
    
    return camelized_string


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


def handle_call_action(request: ActionRequest):
    # Write your code below
    contact = get_friend_by_request(request)
    if contact:
        return "🤙 Calling " + contact + " ..."
    else:
        return request.username + ", I can't find this person in your contacts."


def handle_reminder_action(action: str):
    # Write your code below
    return "🔔 Alright, I will remind you!"


def handle_timer_action(action: str):
    # Write your code below
    return "⏰ Alright, the timer is set!"


def handle_unknown_action(action: str):
    # Write your code below
    return "👀 Sorry , but I can't help with that!"

def verify_user(username: str):
    """Verifies that the user is known"""
    if username in friends:
        return True
    return False

def get_friend_by_request(request: ActionRequest):
    """Tries to find a contact in the request, returns the contact on success and False on failure"""
    contact_list = friends[request.username]
    for contact in contact_list:
        if contact in request.action:
            return contact
    return False


def get_handler_by_action(action: str):
    """Looks for certain keywords in the action and chooses the corresponding handler"""
    available_handlers = {
        "call": handle_call_action,
        "remind": handle_reminder_action,
        "timer": handle_timer_action
    }
    lowercase_action = action.lower()

    for keyword in available_handlers.keys():
        if keyword in lowercase_action:
            return available_handlers[keyword]

    return handle_unknown_action


@app.post("/task3/action", tags=["Task 3"], summary="🤌")
def task3_action(request: ActionRequest):
    """Accepts an action request, recognizes its intent and forwards it to the corresponding action handler."""
    # tip: you have to use the response model above and also might change the signature
    #      of the action handlers
    # Write your code below

    if verify_user(request.username):
        handler = get_handler_by_action(request.action)
    else:
        return ActionResponse(message="Hi "+request.username+", I don't know you yet. But I would love to meet you!")
    
    return ActionResponse(message=handler(request))


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
    unauthorized_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Incorrect username or password"
    )

    fake_user = get_user(form_data.username)
    if not fake_user:
        raise unauthorized_exception

    fake_password = verify_password(form_data.password, fake_user.hashed_password)
    if not fake_password:
        raise unauthorized_exception

    
    payload = {
        "sub": fake_user.username,
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

        if username is None:
            raise credentials_exception

    except JWTError:
            raise credentials_exception

    return get_user(username)


@app.get("/task4/users/{username}/secret", summary="🤫", tags=["Task 4"])
async def read_user_secret(
    username: str, current_user: User = Depends(get_current_user)
):
    """Read a user's secret."""
    # uppps 🤭 maybe we should check if the requested secret actually belongs to the user
    # Write your code below

    if (user := get_user(username)) and user == current_user:
        return user.secret
        
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Don't spy on other user!"
    )


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
