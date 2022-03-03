from fastapi import FastAPI
import re

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
    args = locals()
    lang_dict={
        "de":"Hallo {name}, ich bin Emilia.",
        "en":"Hello {name}, I am Emilia.",
        "es":"Hola {name}, soy Emilia."
    }
    default = "Hallo {name}, leider spreche ich nicht '{language}'!"
    return lang_dict.get(language,default).format(**args)
    # -> This is a more simple approach
    if language == "de": 
        return f"Hallo {name}, ich bin Emilia."
    elif language == "en":
        return f"Hello {name}, I am Emilia."
    elif language == "es":
        return f"Hola {name}, soy Emilia."
    else: 
        return f"Hallo {name}, leider spreche ich nicht '{language}'!"



"""
Task 2 - snake_case to cameCase
"""

from typing import Any

def get_match_from_wasted_match(match: re.Match):
    """ This gets the actual matched string from the totally useless match object that noone ever needs. 
    The only thing you'll ever need is the matched string. """
    return match.string[match.start():match.end()]

def camelize(key: str)->str:
    """Takes string in snake_case format and returns camelCase formatted version."""
    # Write your code below
    pattern = re.compile(r"_.") # any underscore followed by any character
    key = re.sub(pattern,lambda match: get_match_from_wasted_match(match)[1].upper(), key) #we replace with a capital letter
    return key


@app.post("/task2/camelize", tags=["Task 2"], summary="🐍➡️🐪")
async def task2_camelize(data: dict[str, Any]) -> dict[str, Any]:
    """Takes a JSON object and transforms all keys from snake_case to camelCase."""
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


def handle_call_action(request: ActionRequest)->str:
    # Write your code below
    from string import punctuation
    def delete_chars(text: str, chars: list[str])-> str:
        for char in chars:
            text = text.replace(char, "")
            return text
    for name in friends[request.username]:
        if name in request.action:
            return f"🤙 Calling {name} ..."
    enum = list(enumerate(request.action.split(" ")))
    for i,name in enum:
        if not i==0:
            if not enum[i-1][-1]=="." and name[0].isupper():
                print("Very likely a name (at least in English):", delete_chars(name, punctuation))
    return f"{request.username}, I can't find this person in your contacts."


def handle_reminder_action(_: ActionRequest)->str:
    # Write your code below
    ...
    return "🔔 Alright, I will remind you!" # a bit lazy


def handle_timer_action(_: ActionRequest)->str:
    # Write your code below
    ...
    return "⏰ Alright, the timer is set!" # a bit lazy too


def handle_unknown_action(_: ActionRequest)->str:
    # Write your code below
    ...
    return "👀 Sorry , but I can't help with that!" # also lazy


@app.post("/task3/action", tags=["Task 3"], summary="🤌")
def task3_action(request: ActionRequest):
    """Accepts an action request, recognizes its intent and forwards it to the corresponding action handler."""
    # tip: you have to use the response model above and also might change the signature
    # of the action handlers
    from string import punctuation
    from typing import Callable
    def delete_chars(text: str, chars: list[str])-> str:
        for char in chars:
            text = text.replace(char, "")
            return text
    def words(text: str)->list[str]: # a bit like tokenization. But the stemming is missing. Which might be especially useful for eg: Remind/reminder
        text = delete_chars(text, punctuation).lower()
        return text.split(" ") # instead of just a regular split
    handle = Callable[[ActionRequest],str]
    options: list[tuple[list[str],handle]]=[
        (["call"],handle_call_action),
        (["remind","reminder"],handle_reminder_action),
        (["timer"],handle_timer_action)
    ]
    # we'll just do simple word searches. 
    # Nothing crazy like NLP. 
    # But if I had a dictionary or so it would be pretty easy to find out what words are likely names 
    # also a frequency dict could be good for filtering out unimportant words and finding the most important ones. 
    if request.username not in friends: #unknown user
        return {
            "message":f"Hi {request.username}, I don't know you yet. But I would love to meet you!"
            }
    else:
        handler: handle = handle_unknown_action
        ws = words(request.action)
        for keys,func in options:
            for k in keys:
                if k in ws:
                    handler = func
                    break # very simple, in reality we would give every possible handler a likeliness score
        return {
            "message":handler(request)
            }


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
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Incorrect username or password"
    )
    if (user:=get_user(form_data.username)) is not None and verify_password(form_data.password,user.hashed_password):
        payload = {
            "sub": form_data.username,
            "exp": datetime.utcnow() + timedelta(minutes=30),
        }
        return {
            "access_token": encode_jwt(payload),
            "token_type": "bearer",
        }
    else:
        raise credentials_exception


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
        assert None not in (payload.get("exp"), (username:=payload.get("sub")))
        return get_user(username)
    except:
        raise credentials_exception

    


@app.get("/task4/users/{username}/secret", summary="🤫", tags=["Task 4"])
async def read_user_secret(
    username: str, current_user: User = Depends(get_current_user)
):
    """Read a user's secret."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Don't spy on other user!"
    )
    # Write your code below
    ...
    if user := get_user(username):
        if current_user is not None and current_user == user:
            return user.secret
        else:
            raise credentials_exception


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
for i in range(1,5):
    task = messages[f"task{i}"]
    info = partial(identity, task["info"])
    help_ = partial(identity, task["help"])
    tags = [f"Task {i}"]
    app.get(f"/task{i}", summary="📝", description=info(), tags=tags)(info)
    app.get(f"/task{i}/help", summary="🙋", description=help_(), tags=tags)(help_)
