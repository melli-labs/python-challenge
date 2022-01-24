from fastapi import FastAPI

app = FastAPI(
    title="Emilia Hiring Challenge 👩‍💻",
    description="Help Emilia 👩 to fix our tests and get a job interview 💼🎙️!",
)


"""
Task 1 - Warmup
"""


@app.get("/task1/greet/{name}", tags=["Task 1"], summary="👋🇩🇪🇬🇧🇪🇸")
async def task1_greet(name: str, language=None) -> str:
    """Greet somebody in German, English or Spanish!"""
    if language is None or language=='de':
        return f"Hallo {name}, ich bin Emilia."
    elif language=='en':
        return f"Hello {name}, I am Emilia."
    elif language == 'es':
        return f"Hola {name}, soy Emilia."
    else:
        return f"Hallo Ben, leider spreche ich nicht '{language}'!"


"""
Task 2 - snake_case to cameCase
"""

from typing import Any


def camelize(key: str):
    """Takes string in snake_case format returns camelCase formatted version."""
    # Write your code below
    key_list = key.split('_')   # split wherever there is an underscore
    # each character after an underscore gets capitalized. Join string.
    key_camelized = ''.join([key_list[0]]+[s.title() for s in key_list[1::]])

    return key_camelized


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


def handle_call_action(action):
    # Write your code below

    for name in friends[action.username]:
        if name in action.action:
            return {'message':f"🤙 Calling {name} ..."}
    return {'message':f"{action.username}, I can't find this person in your contacts."}
    

def handle_reminder_action(action):
    # Write your code below
    return {'message':"🔔 Alright, I will remind you!"}


def handle_timer_action(action):
    # Write your code below
    return {'message':"⏰ Alright, the timer is set!"}


def handle_unknown_action(actioon):
    # Write your code below
    return {'message':"👀 Sorry , but I can't help with that!"}

def handle_user_unknown(action):
    return {'message':f"Hi {action.username}, I don't know you yet. But I would love to meet you!"}

@app.post("/task3/action", tags=["Task 3"], summary="🤌")
def task3_action(request: ActionRequest):
    """Accepts an action request, recognizes its intent and forwards it to the corresponding action handler."""
    # tip: you have to use the response model above and also might change the signature
    #      of the action handlers
    # Write your code below
    
    # Explanation: 
    # I comparing the words in the action request to key terms.
    # To assess the similarity between words, I use vector representations by a FastText model.
    # The maximum cosine similarity among words in the action requests is computed for all key terms.
    # The action handler matching the key word with the highest similarity is selected.

    from gensim.models.fasttext import load_facebook_model                  # gensim version 4.1.2 
    from gensim.test.utils import datapath

    if request.username not in friends:
        return handle_user_unknown(request)

    sample_string_list =  request.action[:].casefold().split()              # list of lowercase words
    model = load_facebook_model(datapath("crime-and-punishment.bin")).wv    # pretrained FastText model
    key_terms = ['call', 'timer', 'remind'] 
    handler_dict = dict(zip(key_terms, [handle_call_action, handle_timer_action,handle_reminder_action]))
    similarity_thresh = 0.96  
    similarities = [max(model.similarity(s, kt) for s in sample_string_list) for kt in key_terms]
    max_similarities = max(similarities)

    if max_similarities>similarity_thresh:
        handler=handler_dict[key_terms[similarities.index(max_similarities)]]
    else:
        handler=handle_unknown_action
    return handler(request)

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
    user = get_user(form_data.username)
    if user is not None:
        if verify_password(secret=form_data.password, hash=user.hashed_password):

            payload = {
                "sub": form_data.username,
                "exp": datetime.utcnow() + timedelta(minutes=30),
            }
            return {
                "access_token": encode_jwt(payload),
                "token_type": "bearer",
                }  
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Incorrect username or password")


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
         
    user =  get_user(decode_jwt(token)["sub"])
    if user is None:
        raise (credentials_exception)
    else:
         return user


@app.get("/task4/users/{username}/secret", summary="🤫", tags=["Task 4"])
async def read_user_secret(
    username: str, current_user: User = Depends(get_current_user)
):
    """Read a user's secret."""
    # uppps 🤭 maybe we should check if the requested secret actually belongs to the user
    # Write your code below
    if current_user==get_user(username):
        return current_user.secret
    else: 
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Don't spy on other user!")
   


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
