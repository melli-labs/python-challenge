from datetime import datetime, timedelta
from enum import Enum
from functools import partial
from pathlib import Path
from typing import Any, Optional, Tuple, List

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import PlainTextResponse
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from tomlkit.api import parse
from abc import ABC, abstractmethod

app = FastAPI(
    title="Melli Hiring Challenge 👩‍💻",
    description="Help Melli 👩 to fix our tests and get a job interview 💼🎙️!",
)


"""
Task 1 - Warmup
"""


class Language(Enum):
    """ Enum for handling the supported languages in one place. Single Source Of Truth."""
    spanish = "es"
    english = "en"
    german = "de"


text_for_app = {
    "de": {"greeting": "Hallo name_var, ich bin Melli."},
    "en": {"greeting": "Hello name_var, I am Melli."},
    "es": {"greeting": "Hola name_var, soy Melli."},
    "not supported": {"greeting": "Hallo name_var, leider spreche ich nicht 'language_var'!"}
}


def valid_language(language: Optional[str] = "de") -> tuple:
    if not language in [lang.value for lang in Language]:
        return ("not supported", language)

    return ("supported", language)


@app.get("/task1/greet/{name}", tags=["Task 1"], summary="👋🇩🇪🇬🇧🇪🇸")
async def task1_greet(name: str, language: Tuple[str, str] = Depends(valid_language)) -> str:
    """Greet somebody in German, English or Spanish!"""
    if language[0] == "not supported":
        return text_for_app[language[0]]["greeting"].replace("name_var", name).replace("language_var", language[1])

    if language[0] == "supported":
        return text_for_app[language[1]]["greeting"].replace("name_var", name)


"""
Task 2 - snake_case to cameCase
"""

def is_snake_case(key):
    """Check that all chars are lowercase, at least one underscore is included and there is not number at first position."""

    key_bools = [False, False, False]
    print(key)
    if key.islower():
        key_bools[0] = True

    if "_" in key:
        key_bools[1] = True

    if not key[0].isnumeric():
        key_bools[2] = True

    return set(key_bools) == {True}

def camelize(key: str):
    """Takes string in snake_case format returns camelCase formatted version."""
    # Write your code below
    if is_snake_case(key):
        key_list = key.split("_")
        rest_list = "".join([k.title() for k in key_list[1:]])
        return f"{key_list[0]}{rest_list}"
    else:
        raise HTTPException(
            status_code=422, detail="Ups, das wird nicht funktionieren, da der von dir bereitgestellte String nicht der Snake Case Convention folgt."
        )
    
    return key


@app.post("/task2/camelize", tags=["Task 2"], summary="🐍➡️🐪")
async def task2_camelize(data: dict[str, Any]) -> dict[str, Any]:
    """Takes a JSON object and transfroms all keys from snake_case to camelCase."""
    return {camelize(key): value for key, value in data.items()}


"""
Task 3 - Handle User Actions
"""




class ActionRequest(BaseModel):
    username: str
    action: str


class ActionResponse(BaseModel):
    message: str

class Action(ABC):

    @abstractmethod
    def execute(self, action: str, user_friends: List[str], user: Optional[str] = None):
        pass

class Call(Action):
    intent = "call"
    
    def execute(self, action: str, user_friends: List[str], user: Optional[str] = None):
        # Write your code below

        if not user:
            raise HTTPException(
                status_code=409, detail="This error is unexpected. Please make sure to provide an existing username."
            )

        for u_f in user_friends:
            if u_f in action:
                return f"🤙 Calling {u_f} ..."
              
        return f"{user}, I can't find this person in your contacts."

class Reminder(Action):
    intent = "remind"

    def execute(self, action: str, user_friends: List[str], user: Optional[str] = None):
        return "🔔 Alright, I will remind you!"

class Timer(Action):
    intent = "timer"

    def execute(self, action: str, user_friends: List[str], user: Optional[str] = None):
        return "⏰ Alright, the timer is set!"

class Unknown(Action):
    intent = "unknown"

    def execute(self, action: str, user_friends: List[str], user: Optional[str] = None):
        return "👀 Sorry , but I can't help with that!"

call_action = Call()
reminder_action = Reminder()
timer_action = Timer()
unknown_action = Unknown()

class ActionHandler():
    actions = [call_action, reminder_action, timer_action, unknown_action]


    def __init__(self) -> None:
        self.friends = {
            "Matthias": ["Sahar", "Franziska", "Hans"],
            "Stefan": ["Felix", "Ben", "Philip"],
        }

    def decide(self, intent: str):
        for action in self.actions:
            if intent == action.intent:
                return action

class Intention():
    def __init__(self) -> None:
        pass

    def recognize(self, text: str):
        print(text.lower())
        if "call" in text.lower():
            return "call"
        if "remind" in text.lower():
            return "remind"
        if "timer" in text.lower():
            return "timer"
        
        return "unknown"

intention = Intention()

action_handler = ActionHandler()

@app.post("/task3/action", tags=["Task 3"], summary="🤌", response_model=ActionResponse)
def task3_action(request: ActionRequest):
    """Accepts an action request, recognizes its intent and forwards it to the corresponding action handler."""
    # tip: you have to use the response model above and also might change the signature
    #      of the action handlers
    # Write your code below
    user = request.username

    if user not in action_handler.friends.keys():
        return ActionResponse(
            message = f"Hi {user}, I don't know you yet. But I would love to meet you!"
        )

    intent = intention.recognize(request.action)
    
    user_friends = action_handler.friends[user]

    action = action_handler.decide(intent)
    
    return ActionResponse(message=action.execute(request.action, user_friends, user))


"""
Task 4 - Security
"""

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
        "email": "stefan.buchkremer@melli.com",
        "hashed_password": hash_password("decent-espresso-by-john-buckmann"),
        "secret": "I love pressure-profiled espresso ☕!",
    },
    "felix": {
        "username": "felix",
        "email": "felix.andreas@melli.com",
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

messages = parse((Path(__file__).parent / "messages.toml").read_text("utf-8"))


@app.get("/", summary="👋", tags=["Melli"])
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
