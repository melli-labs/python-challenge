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

    # Write your code below
    if language == "en":
        greet = f"Hello {name}, I am Emilia."
    elif language == "es":
        greet = f"Hola {name}, soy Emilia."
    elif language == "de":
        greet = f"Hallo {name}, ich bin Emilia."
    else:
        greet = f"Hallo {name}, leider spreche ich nicht '{language}'!"

    return greet


"""
Task 2 - snake_case to cameCase
"""

from typing import Any


def camelize(key: str):
    """Takes string in snake_case format returns camelCase formatted version."""

    # Write your code below
    tmpl = key.split("_")
    tmplength = len(tmpl)
    key = tmpl[0]

    for i in range(1, tmplength):
        key += tmpl[i].capitalize()
    return key


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


def handle_call_action(username: str, action: str):
    # Write your code below

    valid_contacts = friends[username]
    name = ""

    for friend in valid_contacts:
        result = re.search(friend, action)
        if result != None:
            name = result.group()

    if len(name) != 0:
        answer = {"message": f"🤙 Calling {name} ..."}
    else:
        answer = {"message": f"{username}, I can't find this person in your contacts."}

    return answer


def handle_reminder_action(action: str):
    # Write your code below

    answer = {"message": "🔔 Alright, I will remind you!"}
    return answer


def handle_timer_action(action: str):
    # Write your code below

    answer = {"message": "⏰ Alright, the timer is set!"}
    return answer


def handle_unknown_action(action: str):
    # Write your code below

    answer = {"message": "👀 Sorry , but I can't help with that!"}
    return answer


@app.post("/task3/action", tags=["Task 3"], summary="🤌")
def task3_action(request: ActionRequest):
    """Accepts an action request, recognizes its intent and
    forwards it to the corresponding action handler.
    """
    # tip: you have to use the response model above and also might change the signature
    #      of the action handlers
    # Write your code below

    # Sanity check: Check whether username exists or not:
    legal_usernames = []
    for user in friends.keys():
        legal_usernames.append(user)
    if request.username not in legal_usernames:
        return {
            "message": f"Hi {request.username}, I don't know you yet. But I would love to meet you!"
        }

    # Initialize actions
    action_list = request.action.lower().split(" ")
    call_action = ["call", "calling"]
    remind_action = ["remind"]
    timer_action = ["set", "timer"]

    # Catch unknow_action
    check_action = False

    # Ceck for a call
    for action in call_action:
        if action in action_list:
            check_action = True
            return handle_call_action(request.username, request.action)

    # Check for a reminder
    if remind_action[0] in action_list:
        check_action = True
        return handle_reminder_action(request.action)

    # Check for a timer
    for action in timer_action:
        if action in action_list:
            check_action = True
            return handle_timer_action(request.action)

    # Unkown action
    if check_action == False:
        return handle_unknown_action(request.action)


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
from typing import Union


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

# Create a list with all registerd users
valid_users = []
for key, item in fake_users_db.items():
    for user in item.keys():
        if user == "username":
            valid_users.append(item[user])


class User(BaseModel):
    username: str
    email: str
    hashed_password: str
    secret: str


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Union[str, None] = None


@app.post("/task4/token", response_model=Token, summary="🔒", tags=["Task 4"])
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """Allows registered users to obtain a bearer token."""
    # fixme 🔨, at the moment we allow everybody to obtain a token
    # this is probably not very secure 🛡️ ...
    # tip: check the verify_password above
    # Write your code below

    username = form_data.username
    password = form_data.password

    if authenticate_user(username, password):
        payload = {
            "sub": form_data.username,
            "exp": datetime.utcnow() + timedelta(minutes=30),
        }
        return {
            "access_token": encode_jwt(payload),
            "token_type": "bearer",
        }
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )


def authenticate_user(username, password):
    """Return True if user is registererd
    otherwise return False
    """

    if username in valid_users:
        password_check = _crypt_context.verify(
            password, fake_users_db[username]["hashed_password"]
        )
        return password_check
    else:
        return False


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
        payload = jwt.decode(token, key=SECRET_KEY, algorithms=[ALOGRITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(username=token_data.username)
    if user is None:
        raise credentials_exception
    return user


@app.get("/task4/users/{username}/secret", summary="🤫", tags=["Task 4"])
async def read_user_secret(
    username: str, current_user: User = Depends(get_current_user)
):
    """Read a user's secret."""
    # uppps 🤭 maybe we should check if the requested secret actually belongs to the user
    # Write your code below
    user = get_user(username)

    if user == current_user:
        return user.secret
    else:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Don't spy on other user!"
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
