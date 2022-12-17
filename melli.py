from fastapi import FastAPI
from typing import Union

app = FastAPI(
    title="Melli Hiring Challenge 👩‍💻",
    description="Help Melli 👩 to fix our tests and get a job interview 💼🎙️!",
)


"""
Task 1 - Warmup
"""


@app.get("/task1/greet/{name}", tags=["Task 1"], summary="👋🇩🇪🇬🇧🇪🇸")
async def task1_greet(name: str, language: Union[str, None] = None) -> str:
    """Greet somebody in German, English or Spanish!"""
    if not language or language == "de":
        answer = f"Hallo {name}, ich bin Melli."
    elif language == "en":
        answer = f"Hello {name}, I am Melli."
    elif language == "es":
        answer = f"Hola {name}, soy Melli."
    else:
        answer = f"Hallo {name}, leider spreche ich nicht '{language}'!"
    return answer


"""
Task 2 - snake_case to cameCase
"""

from typing import Any


def camelize(key: str):
    """Takes string in snake_case format returns camelCase formatted version."""
    words = key.split("_")
    key = "".join(word.title() for word in words)
    key = key[0].lower() + key[1:]
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


def handle_call_action(action: str, username: str, friend: str):
    if friend not in friends.get(username, []):
        return ActionResponse(message=f"{username}, I can't find this person in your contacts.")
    return ActionResponse(message=f"🤙 Calling {friend} ...")


def handle_reminder_action(action: str):
    # Write your code below
    ...
    return ActionResponse(message="🔔 Alright, I will remind you!")


def handle_timer_action(action: str):
    # Write your code below
    ...
    return ActionResponse(message="⏰ Alright, the timer is set!")


def handle_unknown_action(action: str):
    # Write your code below
    ...
    return ActionResponse(message="👀 Sorry , but I can't help with that!")


@app.post("/task3/action", tags=["Task 3"], summary="🤌")
def task3_action(request: ActionRequest):
    """Accepts an action request, recognizes its intent and forwards it to the corresponding action handler."""
    # tip: you have to use the response model above and also might change the signature
    #      of the action handlers
    import json
    import requests

    # Helper function to query HuggingFace API
    def query_nlp(query_string, model="pucpr-br/postagger-bio-english"):
        data = json.dumps({"inputs": query_string})
        res = requests.post(
            url=f"https://api-inference.huggingface.co/models/{model}",
            headers={"Authorization": f"Bearer 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"},
            data=data,
            timeout=30  # Necessary sometimes, if model is not cached on huggingface.co
        )
        return json.loads(res.content.decode("utf-8"))

    # Catch unknown users trying to access Melli
    if request.username not in friends.keys():
        return ActionResponse(message=f"Hi {request.username}, I don't know you yet. But I would love to meet you!")

    # Query NLP API to determine the desired action
    nlp_response_words = query_nlp(request.action, model="pucpr-br/postagger-bio-english")
    verbs = [_.get("word").lower() for _ in nlp_response_words if _["entity_group"] in ["VB", "VBP"]]
    nouns = [_.get("word").lower() for _ in nlp_response_words if _["entity_group"] == "NN"]

    # Query NLP API to get names mentioned
    nlp_response_names = query_nlp(request.action, model="Davlan/bert-base-multilingual-cased-ner-hrl")
    names = [_.get("word") for _ in nlp_response_names if _["entity_group"] == "PER"]

    # Determine action handler
    if "remind" in verbs:
        response = handle_reminder_action(action=request.action)
    elif "call" in verbs:
        if len(names) != 1:
            return handle_unknown_action(action=request.action)
        response = handle_call_action(action=request.action, username=request.username, friend=names[0])
    elif "timer" in nouns:
        response = handle_timer_action(action=request.action)
    else:
        response = handle_unknown_action(action=request.action)
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
    login_exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password"
        )

    # Check username
    user = get_user(form_data.username)
    if not user:
        raise login_exception

    # Check password
    if not verify_password(form_data.password, user.hashed_password):
        raise login_exception

    # Issue new token
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
        headers={"WWW-Authenticate": "Bearer"}
    )
    # check if the token 🪙 is valid and return a user as specified by the tokens payload
    # otherwise raise the credentials_exception above

    # Verify token
    try:
        payload = decode_jwt(token)
    except:
        raise credentials_exception
    print(f"{payload}")

    # Get user from db
    username = payload.get("sub")
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

    if username != current_user.username:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Don't spy on other user!",
            headers={"WWW-Authenticate": "Bearer"}
        )

    return current_user.secret


"""
Task and Help Routes
"""

from functools import partial
from pathlib import Path

from tomlkit.api import parse

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
