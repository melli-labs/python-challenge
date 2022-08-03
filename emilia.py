from fastapi import FastAPI

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
    # Write your code below
    if language in ["en", "es", "de"]:
        if language == "en":
            return f"Hello {name}, I am Emilia."
        elif language == "es":
            return f"Hola {name}, soy Emilia."
        elif language == "de":
            return f"Hallo {name}, ich bin Emilia."
    else:
        return f"Hallo Ben, leider spreche ich nicht '{language}'!"


"""
Task 2 - snake_case to cameCase
"""

from typing import Any


def camelize(key: str):
    """Takes string in snake_case format returns camelCase formatted version."""
    words = key.split("_")
    return words[0] + "".join(word.title() for word in words[1:])     

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


def handle_call_action(request: dict):
    user = request["username"]
    friends_list = [name.lower() for name in friends[user]]
    friend = None    
    for word in request["action"]:
        if word.lower() in friends_list:
            friend = word.lower()
            
    if friend != None:
        return ActionResponse(message= f"🤙 Calling {friend.capitalize()} ...")
    else:
        return {"message": f"{user}, I can't find this person in your contacts."}

def handle_reminder_action(request: dict):
    return ActionResponse(message= "🔔 Alright, I will remind you!")
        
def handle_timer_action(request: dict):
    return ActionResponse(message= "⏰ Alright, the timer is set!")

@app.post("/task3/action", tags=["Task 3"], summary="🤌")
def task3_action(request: ActionRequest):
    """Accepts an action request, recognizes its intent and forwards it to the corresponding action handler."""
    # tip: you have to use the response model above and also might change the signature
    #      of the action handlers
    # Write your code below
    request_words = [word.lower() for word in request.action.split(" ")]
    user = request.username
    clean_words = []

    if request.username in friends.keys():
        for word in request_words:
            letters = filter(str.isalnum, word)
            clean_word = "".join(letters)
            clean_words.append(clean_word)
        request =  {"username": user, "action": clean_words}

        if "call" in request_words:
            return handle_call_action(request)
        elif "remind" in request_words:
            return handle_reminder_action(request)
        elif "timer" in request_words:
            return handle_timer_action(request)
        else:
            return ActionResponse(message= "👀 Sorry , but I can't help with that!")
    else:
        return ActionResponse(message= f"Hi {request.username}, I don't know you yet. But I would love to meet you!")

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
    if form_data.username not in fake_users_db:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password")
    hashed_password = fake_users_db[form_data.username]["hashed_password"]

    if not verify_password(form_data.password, hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password")
    else:
        access_token_expires = timedelta(minutes=5)
        access_token = encode_jwt({"sub": form_data.username, "exp": datetime.utcnow() + access_token_expires})
        return {"access_token": access_token, "token_type": "bearer"}


def get_user(username: str) -> Optional[User]:
    if username not in fake_users_db:
        return None
    return User(**fake_users_db[username])


async def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid authentication credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        payload = decode_jwt(token)
        username: str = payload["sub"]
        token_expires = payload["exp"]
        token_expires_datetime = datetime.fromtimestamp(token_expires)
        if token_expires_datetime < datetime.utcnow():
            raise credentials_exception
        return payload
    except JWTError:
        raise credentials_exception
    

@app.get("/task4/users/{username}/secret", summary="🤫", tags=["Task 4"])
async def read_user_secret(
    username: str, current_user: User = Depends(get_current_user)
):
    """Read a user's secret."""
    if username != current_user["sub"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN , detail="Don't spy on other user!")
    try:
        user = get_user(username)
        return user.secret
    except e as Exception:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=e)
    
    


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
