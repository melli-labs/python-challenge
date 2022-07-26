from fastapi import FastAPI

app = FastAPI(
    title="Emilia Hiring Challenge 👩‍💻",
    description="Help Emilia 👩 to fix our tests and get a job interview 💼🎙️!",
)


"""
Task 1 - Warmup
"""

from typing import Union


@app.get("/task1/greet/{name}", tags=["Task 1"], summary="👋🇩🇪🇬🇧🇪🇸")
async def task1_greet(name: str, language: Union[str, None]  = None) -> str:
    """Greet somebody in German, English or Spanish!"""
    # Write your code below

    # solution 2
    # dictonary with languages-keys
    response_languages = {
        'de':f"Hallo {name}, ich bin Emilia.",
        'en':f"Hello {name}, I am Emilia.",
        'es':f"Hola {name}, soy Emilia."
    }

    # check language
    if language == None:
        return f"Hallo {name}, ich bin Emilia."
    elif language in response_languages:
        return response_languages[language]
    else:
        return f"Hallo {name}, leider spreche ich nicht '{language}'!"


"""
Task 2 - snake_case to cameCase
"""

from typing import Any


def camelize(key: str):
    """Takes string in snake_case format returns camelCase formatted version."""
    # Write your code below
    splitted_snake_case = key.split('_')

    camelCase_key = splitted_snake_case[0].lower() # first string is always lowercase

    # add other word first char uppercase
    for i in splitted_snake_case[1:]:
        camelCase_key = camelCase_key + i.capitalize()
    return camelCase_key


@app.post("/task2/camelize", tags=["Task 2"], summary="🐍➡️🐪")
async def task2_camelize(data: dict[str, Any]) -> dict[str, Any]:
    """Takes a JSON object and transfroms all keys from snake_case to camelCase."""
    return {camelize(key): value for key, value in data.items()}


"""
Task 3 - Handle User Actions
"""

from pydantic import BaseModel
import re

friends = {
    "Matthias": ["Sahar", "Franziska", "Hans"],
    "Stefan": ["Felix", "Ben", "Philip"],
}


class ActionRequest(BaseModel):
    username: str
    action: str


class ActionResponse(BaseModel):
    message: str


def handle_call_action(request_dict: dict, friends_list: list):
    # prove is username registered in friend_list
    friends_list_as_pattern = r"\b" + '(' + '|'.join(friends_list) + ')'
    friend_in_list = re.search(friends_list_as_pattern, request_dict.action)
    
    if friend_in_list:
        answer_response = f"🤙 Calling {friend_in_list[0]} ..."
    else:
        answer_response = f"{request_dict.username}, I can't find this person in your contacts."

    return {"message":answer_response}


def handle_reminder_action(action: str):
    # Write your code below
    
    ### WRITE CODE FOR REMINDER? ###
        # Angabe aus der Action ziehen
    return {"message":'🔔 Alright, I will remind you!'}


def handle_timer_action(request_dict: dict):
    # Algorihtmus für den Timer:
        # Zeitangabe aus der action ziehen
            
        # re-Ansatz: Finden von Zeitangaben als
            # int + Zeiteinheit (Sekunde, Minute, Stunde, Tage, ...)
            # float + Zeiteinheit (Sekunde, Minute, Stunde, Tage, ...)
            # string: Zahl als Wort + Zeiteinheit (Sekunde, Minute, Stunde, Tage, ...)
            # DateTime
    return {"message":'⏰ Alright, the timer is set!'}


def handle_unknown_action(request_dict: dict):
    return {"message":"👀 Sorry , but I can't help with that!"}


@app.post("/task3/action", tags=["Task 3"], summary="🤌")
def task3_action(request: ActionRequest):
    """Accepts an action request, recognizes its intent and forwards it to the corresponding action handler."""
    # tip: you have to use the response model above and also might change the signature
    #      of the action handlers
    # Write your code below
    
    # Planung
    # Auswahl welcher Task passieren soll
        # ich habe die Tasks:
            # Eine Person anrufen
                # freunde prüfen
                # Begriffe: 'call', 'calling'
                # pattern: 
            # EInen Erinnerung setzen
                # Begriffe: 'reminde me'
            # Zeit ansagen
                # Begriffe: 'set a timer'
            # nicht verstehen, was passieren soll
                # Begriffe: die nicht in der Liste sind
        # DIe Auswahl darüber das:
            # Version 1: Ich suche alle Wörter raus und suche dann nach den key-words
                # spaCy?

                # über re.serach mit pattern für die drei Tasks

            # Version:    

    # There must be a better way!
    # get data from request
    username = request.username
    user_action = request.action

    # check users
    if username not in friends:
        not_an_user_message = f"Hi {username}, I don't know you yet. But I would love to meet you!"
        return {'message':not_an_user_message}

    # pattern for choice
    call_a_friend_pattern = r"\b(call|calling)"
    set_reminder_pattern = r"\b(remind me)"
    set_a_timer_pattern = r"\b(set a timer)"

    # matches
    call_a_friend_match = re.search(call_a_friend_pattern, user_action.lower())
    set_reminder_match = re.search(set_reminder_pattern, user_action.lower())
    set_a_timer_match = re.search(set_a_timer_pattern, user_action.lower())

    if call_a_friend_match:
        handler = handle_call_action(request, friends[username])
    elif set_reminder_match:
        handler = handle_reminder_action(request)
    elif set_a_timer_match:
        handler = handle_timer_action(request)
    else:
        handler = handle_unknown_action(request)
    return handler


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
