from doctest import register_optionflag
from traceback import print_tb
from urllib import request, response
from fastapi import FastAPI

app = FastAPI(
    title="Emilia Hiring Challenge 👩‍💻",
    description="Help Emilia 👩 to fix our tests and get a job interview 💼🎙️!",
)


"""
Task 1 - Warmup
"""


@app.get("/task1/greet/{name}", tags=["Task 1"], summary="👋🇩🇪🇬🇧🇪🇸")
async def task1_greet(name: str, language:str='de') -> str:
    """Greet somebody in German, English or Spanish!"""
    # Write your code below
    ...
    if language == 'en':
        query = f"Hello {name}, I am Emilia."
    elif language == 'es':
        query = f"Hola {name}, soy Emilia."
    elif language == 'de':
        query = f"Hallo {name}, ich bin Emilia."
    else:
        query = f"Hallo {name}, leider spreche ich nicht '{language}'!"
    return query


"""
Task 2 - snake_case to camelCase
"""

from typing import Any


def camelize(key: str):
    """Takes string in snake_case format returns camelCase formatted version."""
    
    text = key.split('_')
    t2 = ''
    for t in text:
        t2 += str(t).capitalize()
        ch = t2[0].lower()
        key = ch + t2[1::]
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


def handle_call_action(action: str):
    pals = friends[user]
    for pal in pals:
        if pal in action:
            return {'message': f'🤙 Calling {pal} ...'}
        else:
            respond = {
            "message": f"{user}, I can't find this person in your contacts.",
        }
        
    return respond
        

def handle_reminder_action(action: str):
    
    return {
            "message": "🔔 Alright, I will remind you!",
        }


def handle_timer_action(action: str):
    
    return {
            "message": "⏰ Alright, the timer is set!",
        }


def handle_unknown_action(action: str):
    
    return {
            "message": "👀 Sorry , but I can't help with that!",
        }


@app.post("/task3/action", tags=["Task 3"], summary="🤌")
def task3_action(request: ActionRequest):
    global user
    """Accepts an action request, recognizes its intent and forwards it to the corresponding action handler."""
    # tip: you have to use the response model above and also might change the signature
    #      of the action handlers
    # Write your code below
    ...

    # There must be a better way!
    
    handlers =[
            handle_call_action,
            handle_reminder_action,
            handle_timer_action,
            handle_unknown_action,
        ]

    user_req = request.action.lower()
    user = request.username
    if user in friends.keys():
        if 'call' in user_req:
            response = handlers[0](request.action)
        elif 'remind' in user_req:
            response = handlers[1](request.action)
        elif 'timer' in user_req:
            response = handlers[2](request.action)
        else:
            response = handlers[3](request.action)

        ### Of course I could handle these answers inside the action handler functions, but I found it easier and more convinient to write my code here.

    else:
        return {
            "message": f"Hi {user}, I don't know you yet. But I would love to meet you!",
        }
    return response
    


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

    users_list = list(fake_users_db.keys())

    payload = {
        "sub": form_data.username,
        "exp": datetime.utcnow() + timedelta(minutes=30),
    }

    the_user = str(form_data.username)
    print(the_user, fake_users_db[the_user]['hashed_password'])
    if the_user in users_list and form_data.password == fake_users_db[the_user]['hashed_password']:
        return {
            "access_token": encode_jwt(payload),
            "token_type": "bearer",
    }

    return "You are not allowed to obtain a token."


def get_user(username: str) -> Optional[User]:
    if username not in fake_users_db:
        return "You are not allowed to obtain a token."
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


@app.get("/task4/users/{username}/secret", summary="🤫", tags=["Task 4"])
async def read_user_secret(
    username: str, current_user: User = Depends(get_current_user)
):
    """Read a user's secret."""
    # uppps 🤭 maybe we should check if the requested secret actually belongs to the user
    # Write your code below
    ...
    if user := get_user(username):
        return user.secret


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