from pytest import param
from fastapi import FastAPI

app = FastAPI(
    title="Emilia Hiring Challenge 👩‍💻",
    description="Help Emilia 👩 to fix our tests and get a job interview 💼🎙️!",
)


"""
Task 1 - Warmup
"""

@app.get("/task1/greet/{name}", tags=["Task 1"], summary="👋🇩🇪🇬🇧🇪🇸")
async def task1_greet(name: str, language:str = "de") -> str: 
    """Greet somebody in German, English or Spanish!"""
    #Did this while watching Star Wars - Holiday Special, 1978
    if language == "de":
        hello = f"Hallo {name}, ich bin Emilia."
    elif language == "en":
        hello = f"Hello {name}, I am Emilia."
    elif language == "es":
        hello = f"Hola {name}, soy Emilia."
    else:
        hello = f"Hallo {name}, leider spreche ich nicht '{language}'!"
    return hello #f"Hallo {name}, ich bin Emilia."#f"Hello {name}, I am Emilia."


"""
Task 2 - snake_case to cameCase
"""

from typing import Any

def camelize(key: str):
    """Takes string in snake_case format returns camelCase formatted version."""
    key = "".join(k.capitalize() if i>0 else k for i,k in enumerate(key.split("_")))
    ##if that looks wild, here the explicit version:
    #string_list = key.split("_")
    #result_list = []
    #for i, k in enumerate(string_list):
    #   if i==0:
    #       result_list.append(k)
    #   else:
    #       result_list.append(k.capitalize())
    #key = "".join(result_list)
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

#poetry add transformers
#poetry add torch
from transformers import pipeline
import re

intent_classifier = pipeline("zero-shot-classification")
intent_labels = ["call", "remind", "timer"]
users = [user for user in friends.keys()]



class ActionRequest(BaseModel):
    username: str
    action: str


class ActionResponse(BaseModel):
    message: str


def handle_call_action(action: str, username: str):
    # Write your code below
    if username in friends.keys():
        #The following quite simple, but I would be interested in seeing how extracting the friend would work with spaCy#s dep-parser.
        #The syntax can be found here: https://spacy.io/usage/linguistic-features 
        #Than we can exclude the accusative objects depending on the verb "call"
        action_obj = re.sub(r"\?|\.|\!", "", action).split()
        action_target = ""
        for obj in action_obj:
            if obj in friends[username]:
                action_target = obj
                break
        if action_target:
            answer = f"🤙 Calling {action_target} ..." #"🤙 Why don't you call them yourself!"
        else:
            answer = f"{username}, I can't find this person in your contacts." # irgendwie muss der name hierhin
    else: 
        answer =  f"Hi {username}, I don't know you yet. But I would love to meet you!"
    return answer


def handle_reminder_action(action: str, username: str):
    # Nothing more to do here for the test. In a real-case scenario, models like jointBERT would do the slot filling.
    # For a more basic alternative, we could do some regex search such as: action_target = re.search(r"remind me to(.*)").group(1)
    answer = "🔔 Alright, I will remind you!"
    return answer #"🔔 I can't even remember my own stuff!"

def handle_timer_action(action: str, username: str):
    # Test works, but of course more could be done. Here too, jointBERT.
    # As an alternative, we could use spaCy's POS-Tagger/ NER to identify numbers and numerical words.
    # Also here: https://spacy.io/usage/linguistic-features
    answer = "⏰ Alright, the timer is set!"
    return answer #"⏰ I don't know how to read the clock!"


def handle_unknown_action(action: str, username: str):
    return "👀 Sorry , but I can't help with that!" #"🤬 #$!@"


@app.post("/task3/action", tags=["Task 3"], summary="🤌")
def task3_action(request: ActionRequest):
    if request.username not in users:
        return ActionResponse(message=f"Hi {request.username}, I don't know you yet. But I would love to meet you!")
    else:
        """Accepts an action request, recognizes its intent and forwards it to the corresponding action handler."""
        intent = intent_classifier(request.action, intent_labels)
        # Of course this model is too huge for the 3 simple tasks we have. It would probably suffice to do sth like:
        # - if "call" in request.action.lower()
        # - if re.search("call", request.action, flags=re.IGNORECASE)
        # And so on. But I mean hey, just wanted to try out a zero shot model.
        # In a more realistic scenario, I would use JointBERT to get intent and fill slots.

        if intent["scores"][0] >.6:
            intent_label = intent["labels"][0]
            if intent_label == "call":
                handler = handle_call_action
            elif intent_label == "remind":
                handler = handle_reminder_action
            elif intent_label == "timer":
                handler = handle_timer_action
        else:
            handler = handle_unknown_action
        return  ActionResponse(message=handler(request.action, request.username)) #{"message": handler(request.action, request.username)} 


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
