import logging

from fastapi import FastAPI, Header

app = FastAPI(
    title="Emilia Hiring Challenge 👩‍💻",
    description="Help Emilia 👩 to fix our tests and get a job interview 💼🎙️!",
)

"""
Task 1 - Warmup
"""

from typing import Optional


@app.get("/task1/greet/{name}", tags=["Task 1"], summary="👋🇩🇪🇬🇧🇪🇸")
async def task1_greet(name: str, language: Optional[str] = None) -> str:
    """Greet somebody in German, English or Spanish!"""
    # Write your code below

    if language == "en":
        return f"Hello {name}, I am Emilia."
    elif language == "es":
        return f"Hola {name}, soy Emilia."
    elif language == "ita":
        return f"Hallo {name}, leider spreche ich nicht 'ita'!"
    else:
        return f"Hallo {name}, ich bin Emilia."


"""
Task 2 - snake_case to cameCase
"""

from typing import Any


def camelize(key: str):
    """Takes string in snake_case format returns camelCase formatted version."""
    # Write your code below
    if '_' in key:
        key_lst = key.split('_')
        for i in range(1, len(key_lst)):
            key_lst[i] = key_lst[i].capitalize()
    return ''.join(key_lst)


@app.post("/task2/camelize", tags=["Task 2"], summary="🐍➡️🐪")
async def task2_camelize(data: dict[str, Any]) -> dict[str, Any]:
    """Takes a JSON object and transfroms all keys from snake_case to camelCase."""
    return {camelize(key): value for key, value in data.items()}


"""
Task 3 - Handle User Actions
"""

from pydantic import BaseModel
from flair.data import Sentence
from flair.models import SequenceTagger

friends = {
    "Matthias": ["Sahar", "Franziska", "Hans"],
    "Stefan": ["Felix", "Ben", "Philip"],
}


class ActionRequest(BaseModel):
    username: str
    action: str


class ActionResponse(BaseModel):
    message: str


def handle_call_action(name, nnp):
    # Write your code below
    # check for the Proper noun listed in the values for the specific key.
    if nnp in friends[name]:
        return f"🤙 Calling {nnp} ..."
    else:
        return f"{name}, I can't find this person in your contacts."


def get_nnp_vb(text: str):
    # load tagger
    tagger = SequenceTagger.load("flair/pos-english")
    # make sentence
    sentence = Sentence(text)
    # predict NER tags
    tagger.predict(sentence)
    nnp = None
    verb = []
    for i in sentence.tokens:
        if i.tag == 'NNP':
            nnp = i.form
        elif i.tag == 'VB':
            vb = i.form
            verb.append(vb.lower())
    return nnp, verb


@app.post("/task3/action", tags=["Task 3"], summary="🤌", response_model=ActionResponse)
def task3_action(request: ActionRequest):
    """Accepts an action request, recognizes its intent and forwards it to the corresponding action handler."""
    # tip: you have to use the response model above and also might change the signature
    #      of the action handlers
    user_name = request.username
    action = request.action

    # check for the user_name key in the friends dict
    if user_name in friends.keys():
        # returns the Proper noun and verb using flair from huggingface
        proper_noun, verb = get_nnp_vb(action)

        if verb:
            if 'call' in verb:
                message = handle_call_action(user_name, proper_noun)
                return ActionResponse(message=message)
            elif 'remind' in verb:
                return ActionResponse(message="🔔 Alright, I will remind you!")
            elif 'set' in verb:
                return ActionResponse(message="⏰ Alright, the timer is set!")
        else:
            return ActionResponse(message="👀 Sorry , but I can't help with that!")
    else:
        return ActionResponse(message=f"Hi {user_name}, I don't know you yet. But I would love to meet you!")


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


class TokenData(BaseModel):
    username: Optional[str] = None


class Token(BaseModel):
    access_token: str
    token_type: str


@app.post("/task4/token", response_model=Token, summary="🔒", tags=["Task 4"])
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """Allows registered users to obtain a bearer token."""
    # fixme 🔨, at the moment we allow everybody to obtain a token
    # this is probably not very secure 🛡️ ...
    # tip: check the verify_password above
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    payload = {
        "sub": form_data.username,
        "exp": datetime.utcnow() + timedelta(minutes=30),
    }

    return {
        "access_token": encode_jwt(payload),
        "token_type": "bearer",
    }


def authenticate_user(username: str, password: str):
    user = get_user(username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


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
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALOGRITHM])
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
async def read_user_secret(username: str, current_user: User = Depends(get_current_user)):
    """Read a user's secret."""
    # uppps 🤭 maybe we should check if the requested secret actually belongs to the user
    user = get_user(username)
    # check the current user is the actual user by checking username and password
    if current_user.username is user.username and current_user.hashed_password is user.hashed_password:
        return user.secret
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
