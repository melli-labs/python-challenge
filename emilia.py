from unittest import result
from webbrowser import get
from fastapi import FastAPI
import fastapi
import re

app = FastAPI(
    title="Emilia Hiring Challenge 👩‍💻",
    description="Help Emilia 👩 to fix our tests and get a job interview 💼🎙️!",
)

"""
Task 1 - Warmup
"""

@app.get("/task1/greet/{name}", tags=["Task 1"], summary="👋🇩🇪🇬🇧🇪🇸")
async def task1_greet(name: str, language = 'de') -> str:
    """Greet somebody in German, English or Spanish!"""
    # Write your code below
    ...
    if language =="en":
         return f"Hello {name}, I am Emilia."
    if language =="de":
         return f"Hallo {name}, ich bin Emilia."
    if language == "es":
        return f"Hola {name}, soy Emilia."

    return f"Hallo {name}, leider spreche ich nicht '{language}'!"
    

"""
Task 2 - snake_case to cameCase
"""

from typing import Any


def camelize(key: str):
    """Takes string in snake_case format returns camelCase formatted version."""
    # Write your code below

    words = key.split('_')

    tranformed_words = [words[0]]

    for ind,word in enumerate(words):
        if ind == 0:
            continue;
        
        tranformed_words.append(word[0].capitalize() + word[1:])

    key = "".join(tranformed_words)

    print(key)    

    key = "".join(tranformed_words)
    ...
    return key


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


def handle_call_action(username: str,action: str):
    # Write your code below
    ...
    name = None

    call_first_pattern = re.search(r'(?:call|Call) my friend ([A-Z][a-z]+)',action)
    if call_first_pattern:
        name = call_first_pattern.group(1)

    call_second_pattern = re.search(r'Can you call ([A-Z][a-z]+)',action)
    if call_second_pattern:
        name = call_second_pattern.group(1)
    
    call_third_pattern = re.search(r'I haven\'t spoken to ([A-Z][a-z]+) in a long time. Can you call her\?',action)
    if call_third_pattern:
        name = call_third_pattern.group(1)

    friends_list = friends[username]

    if name in friends_list:
        return {"message":  f'🤙 Calling {name} ...'}
    return {"message": f"{username}, I can't find this person in your contacts."}


def handle_reminder_action(username: str, action: str):
    # Write your code below
    ...
    return {"message": "🔔 Alright, I will remind you!"}


def handle_timer_action(username: str,action: str):
    # Write your code below
    ...
    return {"message": "⏰ Alright, the timer is set!"}


def handle_unknown_action(action: str):
    # Write your code below
    ...
    return {"message": "👀 Sorry , but I can't help with that!"}


@app.post("/task3/action", tags=["Task 3"], summary="🤌")
def task3_action(request: ActionRequest):
    """Accepts an action request, recognizes its intent and forwards it to the corresponding action handler."""
    # tip: you have to use the response model above and also might change the signature
    #      of the action handlers
    # Write your code below
    ...
    print(request)
    username = request.username
    action = request.action

    # check if the username exists
    if username not in friends.keys():
        return {"message": f"Hi {username}, I don't know you yet. But I would love to meet you!"}

    if re.search(r'Set a timer for [a-z]+ minutes',action):
        return handle_timer_action(username, action)

    if re.search(r'^Remind', action):
        return handle_reminder_action(username, action)

    if re.search(r'(?:call|Call)',action):
        return handle_call_action(username, action)

    return handle_unknown_action(action)


    # from random import choice

    # # There must be a better way!
    # handler = choice(
    #     [
    #         handle_call_action,
    #         handle_reminder_action,
    #         handle_timer_action,
    #         handle_unknown_action,
    #     ]
    # )
    # return handler(request.action)


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

    username = form_data.username
    password = form_data.password

    try:
        user = fake_users_db[username]
        if user:
            hashed_password = user["hashed_password"];

            result = verify_password(secret=password, hash=hashed_password)

            # if the passwords match
            if (result):
                ...
                payload = {
                    "sub": form_data.username,
                    "exp": datetime.utcnow() + timedelta(minutes=30),
                }
                return {
                    "access_token": encode_jwt(payload),
                    "token_type": "bearer",
                }

            # if the passwords don't match
            raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Incorrect username or password"
                )
        else:
           raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Incorrect username or password"
                )
    except (AttributeError , KeyError):
        raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password"
            )


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
    ...

    try:
        payload = decode_jwt(token=token)
        username = payload["sub"]

        return User(**fake_users_db[username])
    except JWTError:
        raise credentials_exception



@app.get("/task4/users/{username}/secret", summary="🤫", tags=["Task 4"])
async def read_user_secret(
    username: str, current_user: User = Depends(get_current_user)
):
    """Read a user's secret."""
    # uppps 🤭 maybe we should check if the requested secret actually belongs to the user
    # Write your code below
    ...
    user = get_user(username)
    if user.username == current_user.username:
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
