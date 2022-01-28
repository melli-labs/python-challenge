from fastapi import FastAPI

app = FastAPI(
    title="Emilia Hiring Challenge 👩‍💻",
    description="Help Emilia 👩 to fix our tests and get a job interview 💼🎙️!",
)


"""
Task 1 - Warmup
"""


@app.get("/task1/greet/{name}", tags=["Task 1"], summary="👋🇩🇪🇬🇧🇪🇸")
async def task1_greet(name: str, language: str = 'de') -> str:
    """Greet somebody in German, English or Spanish!"""
    # Write your code
    languages_Dict = {"de": f"Hallo {name}, ich bin Emilia.",
                      "en": f"Hello {name}, I am Emilia.",
                      "es": f"Hola {name}, soy Emilia."}
    
    if language in languages_Dict:
	    return languages_Dict[language]
    else:
        return f"Hallo {name}, leider spreche ich nicht '{language}'!"


"""
Task 2 - snake_case to cameCase
"""

from typing import Any


def camelize(key: str):
    """Takes string in snake_case format returns camelCase formatted version."""
    # Write your code below
    ...
    key_parts = key.split('_')
    key_parts[1:] = [p.title() for p in key_parts[1:]]
    key = key_parts[0]+"".join(key_parts[1:])
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


def handle_call_action(username: str, action: str) -> str:
    # Write your code below
    ...
    # get friends of actual user as a list
    usr_friends = friends.get(username)
    # check the specified name in the action whether it exists in the friends list or not
    # if the name exits in friend list return Calling...
    if username not in [*friends]:
        return  {"message": f"Hi {username}, I don't know you yet. But I would love to meet you!"}
    for c_friend in usr_friends:
        if c_friend in action:
            #return {"message": "🤙 Calling {c_friend} ...}
            return {"message" : f"🤙 Calling {c_friend} ..."}


    return {"message": f"{username}, I can't find this person in your contacts."}
    #return "🤙 Why don't you call them yourself!"

def handle_reminder_action(username: str, action: str)-> str:
    # Write your code below
    ...
    if username not in [*friends]:
        return {"message": f"Hi {username}, I don't know you yet. But I would love to meet you!"}
    return {"message": "🔔 Alright, I will remind you!"}
    #return "🔔 I can't even remember my own stuff!"


def handle_timer_action(username: str, action: str)->str:
    # Write your code below
    ...
    if username not in [*friends]:
        return {"message": f"Hi {username}, I don't know you yet. But I would love to meet you!"}
    return {"message": "⏰ Alright, the timer is set!"}
    #return "⏰ I don't know how to read the clock!"


def handle_unknown_action(username:str, action: str) -> str:
    # Write your code below

    return {"message": "👀 Sorry , but I can't help with that!"}

@app.post("/task3/action", tags=["Task 3"], summary="🤌")
def task3_action(request: ActionRequest):
    """Accepts an action request, recognizes its intent and forwards it to the corresponding action handler."""
    # tip: you have to use the response model above and also might change the signature
    #      of the action handlers
    # Write your code below

    # create a handler dictionary to combine the key word and actions
    handler = {
            'call': handle_call_action(request.username, request.action),
            'remind': handle_reminder_action(request.username, request.action),
            'timer': handle_timer_action(request.username, request.action),
            'unknown': handle_unknown_action(request.username, request.action)
    }
    # get the action sentence and return a lowercased string
    New_Action_ = request.action.lower()

    # create a list that includes all known actions
    Actions_list = ['call', 'remind', 'timer']

    # for all actions in the Action_list, look up the string specified in the request
    # if a known action is given in request,then address it to desired function
    for act in Actions_list:
        if act in New_Action_:
            return handler[act]
    return handler['unknown']
    #from random import choice

    # There must be a better way!
    #handler = choice(
    #    [
    #        handle_call_action,
    #        handle_reminder_action,
    #        handle_timer_action,
    #        handle_unknown_action,
    #    ]
    #)
    #return handler(request.action)


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
    username = form_data.username
    user = fake_users_db.get(username)

    if not user:
        raise HTTPException(401, detail="Incorrect username or password")

    password = form_data.password
    if not verify_password(password, user.get('hashed_password')):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail = "Incorrect username or password")
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
    # check if the token 🪙 is valid and return a user as specified by the tokens payload
    # otherwise raise the credentials_exception above
    # Write your code below

    ...
    token_decode = decode_jwt(token)
    username = token_decode.get('sub')
    user = get_user(username)
    if not user:
        raise credentials_exception
    return user



@app.get("/task4/users/{username}/secret", summary="🤫", tags=["Task 4"])
async def read_user_secret(
    username: str, current_user: User = Depends(get_current_user)
):
    """Read a user's secret."""
    # uppps 🤭 maybe we should check if the requested secret actually belongs to the user
    # Write your code below
    ...
    if username != current_user.username:
        raise HTTPException(403, detail="Don't spy on other user!")
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

