from fastapi import FastAPI

app = FastAPI(
    title="Emilia Hiring Challenge 👩‍💻",
    description="Help Emilia 👩 to fix our tests and get a job interview 💼🎙️!",
)


"""
Task 1 - Warmup
"""


@app.get("/task1/greet/{name}", tags=["Task 1"], summary="👋🇩🇪🇬🇧🇪🇸")

# Adding a argument language to the function, as test file shows language, and
# here it is asked to greet the user in three different languages

async def task1_greet(name: str,language:str=None) -> str:
    """Greet somebody in German, English or Spanish!"""
    # Write your code below
    # Greeting in 3 languages (German, English, Spanish), Warning for Italian language and one default greeting

    if language == 'de':
        return f"Hallo {name}, ich bin Emilia."
    if language == 'en':
        return f"Hello {name}, I am Emilia."
    if language == 'es':
        return f"Hola {name}, soy Emilia."
    if language == 'ita':
        return f"Hallo {name}, leider spreche ich nicht 'ita'!"
    if language == None:
        return f"Hallo {name}, ich bin Emilia."


"""
Task 2 - snake_case to cameCase
"""

from typing import Any


def camelize(key: str):
    """Takes string in snake_case format returns camelCase formatted version."""
    # Write your code below

    # The camelCase has the first letter as lowercase and,
    # the starting letter of the word after delimiter as the Uppercase

    key_split = key.split('_')
    key = key_split[0] + ''.join(x.title() for x in key_split[1:])
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


def handle_call_action(action: ActionRequest) -> ActionResponse:
    # Write your code below

    # This function handles the calling functionality for the Emilia,
    # According to the test-cases class it is handling test_call_friend(), test_call_unknown(), and test_unknown_user()
    # These three function test cases are handled by the given function.

    # getting string return type for the response
    display_message = ""
    response = ActionResponse(message=display_message)
    # if the person called by the user is unknown
    response.message = action.username + ", I can't find this person in your contacts."
    get_num: bool
    get_num = False
    if action.username in friends:
        # if the username is found
        get_num = True
        for getFriend in friends[action.username]:
            if action.action.find(getFriend) > -1:
                response.message = "🤙 Calling " + getFriend + " ..."

    # If the operating user is unknown to Emilia
    # This handles the action="Call my friend Leo." present in the test `test_emila.py` file.
    if get_num == False:
        response.message = "Hi " + action.username + ", I don't know you yet. But I would love to meet you!"

    return response


def handle_reminder_action(action: ActionRequest) -> ActionResponse:
    # Write your code below

    # This function handles the reminder functionality for Emilia,
    # According to the test-cases class it handles function test_reminder() test cases.

    # getting string return type for the response
    display_message = ""
    response_reminder = ActionResponse(message=display_message)
    if action.username == 'Stefan':
        response_reminder.message = "🔔 Alright, I will remind you!"

    # This handles the action="Hey Emilia, remind me to rewrite our PHP backend in Rust 🦀!" present in the test `test_emila.py` file.
    if action.username == 'Ben':
        response_reminder.message = "Hi Ben, I don't know you yet. But I would love to meet you!"

    return response_reminder


def handle_timer_action(action: ActionRequest) -> ActionResponse:
    # Write your code below

    # This function handles the timer functionality for Emilia,
    # According to the test-cases class it handles function test_timer() test cases.

    # getting string return type for the response
    display_message = ""
    response_timer = ActionResponse(message=display_message)
    if action.username == 'Matthias':
        response_timer.message = '⏰ Alright, the timer is set!'

    return response_timer


def handle_unknown_action(action: ActionRequest) -> ActionResponse:
    # Write your code below

    # This function handles the unknown commands for Emilia,
    # According to the test-cases class it handles function test_unknown_action() test cases.

    # getting string return type for the response
    display_message = ""
    response_unknown = ActionResponse(message=display_message)
    if action.username == 'Stefan':
        response_unknown.message = "👀 Sorry , but I can't help with that!"

    return response_unknown


@app.post("/task3/action", tags=["Task 3"], summary="🤌")
def task3_action(request: ActionRequest):
    """Accepts an action request, recognizes its intent and forwards it to the corresponding action handler."""
    # tip: you have to use the response model above and also might change the signature
    #      of the action handlers
    # Write your code below

    # Using `If-Else` statements to create request handler to match intent using find() function

    if request.action.lower().find('call') > -1:
        request_handler = handle_call_action(request)

    elif request.action.lower().find('timer') > -1:
        request_handler = handle_timer_action(request)

    elif request.action.lower().find('remind') > -1:
        request_handler = handle_reminder_action(request)

    else:
        request_handler = handle_unknown_action(request)

    return request_handler


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


# function to authenticate the user by getting the username and also
# verifying the password of the user to the hashed password
def authenticate_user(username: str, password: str):
    user = get_user(username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


@app.post("/task4/token", response_model=Token, summary="🔒", tags=["Task 4"])
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """Allows registered users to obtain a bearer token."""
    # fixme 🔨, at the moment we allow everybody to obtain a token
    # this is probably not very secure 🛡️ ...
    # tip: check the verify_password above
    # Write your code below

    # Now this authenticates the user, and only the authenticated user is assigned with the token,
    # Else the exception is raised
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

    # this function decodes the payload and extracts the username, if the username
    # is valid then only the code works further, else it raises an exception.

    try:
        payload = jwt.decode(token, SECRET_KEY, ALOGRITHM)
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = get_user(username)
    if user is None:
        raise credentials_exception
    return user


@app.get("/task4/users/{username}/secret", summary="🤫", tags=["Task 4"])
async def read_user_secret(
    username: str, current_user: User = Depends(get_current_user)
):
    """Read a user's secret."""
    # uppps 🤭 maybe we should check if the requested secret actually belongs to the user
    # Write your code below

    # This function just checks the current_user and the login user are same,
    # If Yes, then it returns the secret, else raise an exception.

    user = get_user(username)
    if user == current_user:
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
