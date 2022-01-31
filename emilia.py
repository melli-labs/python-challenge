from __future__ import annotations, barry_as_FLUFL
from xxlimited import foo
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
    ...
    # Define a dictionary of translations
    greetings_translations ={
        "de" : f"Hallo {name}, ich bin Emilia.", 
        "en" : f"Hello {name}, I am Emilia.",
        "es" : f"Hola {name}, soy Emilia."
        }

    # Define an exception string
    greeting_exception = f"Hallo {name}, leider spreche ich nicht '{language}'!"
    
    ### Evaluate what message send to the human 
    # Version 1
    # response = greetings_translations[language] if language in greetings_translations else greeting_exception; 
    # return response

    # Version 2
    # Another way of doing it. More python-esque?
    return greetings_translations.get(language, greeting_exception)


"""
Task 2 - snake_case to cameCase
"""

from typing import Any


def camelize(key: str):
    """Takes string in snake_case format returns camelCase formatted version."""
    # Write your code below
    ...
    
    ### This code is supposed to work for strings with  any_number_of_snake_segments 
    # Split the key-string into its parts and get rid of the _snakey_bits_ at the same time
    key_list = key.split("_")
    # Capitalize the strings in this list, starting with the second one
    key_list_camelized = [part.capitalize() if index > 0 else part for index,part in enumerate(key_list)]
    # Put our camel together 
    key = "".join(key_list_camelized);
    return key


@app.post("/task2/camelize", tags=["Task 2"], summary="🐍➡️🐪")
async def task2_camelize(data: dict[str, Any]) -> dict[str, Any]:
    """Takes a JSON object and transfroms all keys from snake_case to camelCase."""
    
    camelized_data = {camelize(key) : value for key, value in data.items()} 

    return camelized_data


"""
Task 3 - Handle User Actions
"""

from pydantic import BaseModel

#######
# Sections added by me are marked with 7 #s
#
# We get our token to call the huggingface API to use some NLP models. 
# Details below in task3_action (comments, STRATEGY section).
import json
import requests

from configparser import ConfigParser
config = ConfigParser()
config.read('keys_config.cfg')

API_TOKEN = config.get('huggingface', 'api_token')
#######

friends = {
    "Matthias": ["Sahar", "Franziska", "Hans"],
    "Stefan": ["Felix", "Ben", "Philip"],
}


class ActionRequest(BaseModel):
    username: str
    action: str


class ActionResponse(BaseModel):
    message: str


def handle_call_action(person_to_call: str):
    # Write your code below
    ...
    
    message = f"🤙 Calling {person_to_call} ..."

    return {"message": message}

def handle_reminder_action():
    # Write your code below
    ...
    message = "🔔 Alright, I will remind you!"

    return {"message": message}

def handle_timer_action():
    # Write your code below
    ...
    message = "⏰ Alright, the timer is set!"

    return {"message": message}

def handle_unknown_action():
    # Write your code below
    ...
    message = "👀 Sorry , but I can't help with that!"

    return {"message": message}

def handle_unknown_user(username: str):
    # Write your code below
    ...
    message = f"Hi {username}, I don't know you yet. But I would love to meet you!"

    return {"message": message}


#######
# New handlers
def handle_call_unknown_person(username: str):
    message = f"{username}, I can't find this person in your contacts."

    return {"message": message}


def handle_error(): 
    # A token function for error handling
    return "Ooops, something went wrong! Please reload the page (:"


# New utilities
def call_API(payload: str, api_url: str):
    headers = {"Authorization": f"Bearer {API_TOKEN}"}
    data = json.dumps(payload)
    response = requests.request("POST", api_url, headers=headers, data=data)

    return json.loads(response.content.decode("utf-8"))


def get_annotations_0_shot(action: str, triage_labels: list):
    API_URL = "https://api-inference.huggingface.co/models/facebook/bart-large-mnli"
    payload = {
            "inputs": action,
            "parameters": {"candidate_labels": triage_labels},
        }    
    annotations = call_API(payload, API_URL)

    return annotations


def get_annotations_ner(action: str):
    API_URL = "https://api-inference.huggingface.co/models/dbmdz/bert-large-cased-finetuned-conll03-english"
    payload = {
            "inputs": action,
        }
    annotations = call_API(payload, API_URL)

    return annotations


def extract_person_to_call(action: str):
    annotations_ner = get_annotations_ner(action)
    # EXAMPLE RESPONSE
    #     [
    #     {
    #       "entity_group": "PER",
    #       "score": 0.8540124297142029,
    #       "word": "Franziska",
    #       "start": 20,
    #       "end": 29
    #     }
    #   ]
    
    person_to_call = annotations_ner[0]["word"]

    # Ideas for improvement
    # Multiple checks are possible: check that the entity_group is "PER"; check its relationship to the word "call", check that anything even came back, etc. etc. 
    # Handle exception: list is empty -> send special response "I'm sorry, Edward, I didn't understand who you would like to call."

    return person_to_call


@app.post("/task3/action", tags=["Task 3"], summary="🤌")
def task3_action(request: ActionRequest):
    """Accepts an action request, recognizes its intent and forwards it to the corresponding action handler."""
    # tip: you have to use the response model above and also might change the signature
    #      of the action handlers
    # Write your code below
    ...
    
    ### STRATEGY ###
    # 0. Check if the user is registered - which would save us an API call
    # 1. For triage, use a 0-shot classification model through the huggingface API (API_URL_0SHOT). This model seems to do the job very well out of the box.
    # 2. If the result is that the action is a CALL, use another API to scan the action for named entities (API_URL_NER)
    # 2b. Check if the named entity (aka person) is in our user's contacts and send to the appropiate handler
    # 3. If it's not a CALL we're ready to send to the appropiate handler


    ### ACTUAL CODE ### 
    # Our possible actions 
    TRIAGE_LABELS = ["call", "timer", "reminder"]
    failsafe_message = "If you see this, we had an oopsie! Please reload the page." 

    ### 0. Check if user is registered ###
    username = request.username
    registered_users = friends.keys()
    if username not in registered_users: return handle_unknown_user(username)

    ### 1. Triage ###
    # This 0-shot API tries to classify our request.action by assigning probability to each of the TRIAGE_LABELS. 
    # We'll keep it simple for now and just trust its judgement. 
    try:
        annotations_0shot = get_annotations_0_shot(request.action, TRIAGE_LABELS)
        # Take just the list of probabilites from the larger response object
        scores_list = annotations_0shot["scores"]
        print(annotations_0shot)
    except:
        return handle_error()
    
    # The highest value tells us which of our labels is the most likely
    max_score = max(scores_list)

    # If the highest score isn't even that high, we take this to mean that the action is undetermined
    if max_score < 0.6: 
        return handle_unknown_action()
    
    # We correlate the highest score back to the list of labels the API sends back as well.
    # (This list contains the same labels we sent to the API as TRIAGE_LABELS, but sometimes in a different order.)
    index_of_max_score = scores_list.index(max_score)
    corresponding_list_of_labels = annotations_0shot["labels"]
    desired_action = corresponding_list_of_labels[index_of_max_score]
  
    ### 2. User wants to CALL, so we have to find out who...  ###
    # or whom
    if desired_action == "call": 
        try:
            person_to_call = extract_person_to_call(request.action)
        except:
            return handle_error()

        # Also, check if this person is in our user's contacts
        users_contacts = friends[request.username]
        if person_to_call and person_to_call in users_contacts: return handle_call_action(person_to_call)
        else: return handle_call_unknown_person(username)

    ### 3. The desired action is not a CALL ###
    # We could parse it some more, but at this point let's just call the appropiate handlers
    if desired_action == "timer": return handle_timer_action()
    if desired_action == "reminder": return handle_reminder_action()

    # Failsafe
    # The function should never get to here
    # Looking back on this, I don't like this architecture
    return {"message": failsafe_message}

    # Ideas for further improvements:
    # * We find out who our user wants to call by simply filtering out any person's name present in the request. That's called speculation. We could use some syntactic information, to make sure.
    # * Use dependency parsing(?) to figure out what the reminder is for and how long is the timer. That would also allow Emilia to give fuller responses, as in "I'll remind you *to book the tickets* in an hour". This mirroring might be reassuring for the user. 
    # * Use syntactic relations to be more sure about user's intent and catch different request structures: e.g. do a co-reference resolution for pronouns with head == call
    # * Think about edge cases and exceptions, like: user wants to call her friend Emilia, user has two friends named Dorian, user misspoke and wants to cancel
    # * Implement fuzzy search, or at least a "Sorry, can't find a Marty in your contacts. Did You mean Marta?" 
    # * Implement various exception handlers: around failed API calls, longer processing times, etc. etc.
    # * Make the control flow clearer. Right now we have several return statements. If this gets any bigger, it will be hard to see which handler gets called under which conditions. Maybe implement a state machine? 



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
    password = form_data.password

    # We'll use this if the username doesn't exist or the password is incorrect
    credential_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Incorrect username or password",
        headers={"WWW-Authenticate": "Bearer"},
    )

    # Check if user is in our DB
    # We'll just use the get_user function for this, since it was already here and does the job
    user = get_user(username)
    # if not, send a 401
    if user is None: raise credential_exception

    ### This code runs when user is in DB
    # Verify password by comparing hashes
    do_passwords_match = verify_password(password, user.hashed_password)
    # if passwords dont match, send 401
    if not do_passwords_match: raise credential_exception

    ### This code runs when user is in DB and the password is correct
    # send token
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

    # Check if token is valid
    # If not, raise an exception
    try:
        decoded_token = decode_jwt(token)
        username = decoded_token["sub"]
        expiration_time = decoded_token["exp"]
    except: 
        raise credentials_exception

    # Check if the token is expired
    if datetime.utcnow() > datetime.utcfromtimestamp(expiration_time): raise credentials_exception
    
    # This code runs only if the token is valid
    user = fake_users_db[username]

    return user


@app.get("/task4/users/{username}/secret", summary="🤫", tags=["Task 4"])
async def read_user_secret(
    username: str, current_user: User = Depends(get_current_user)
):
    """Read a user's secret."""
    # uppps 🤭 maybe we should check if the requested secret actually belongs to the user
    # Write your code below
    ...

    # I kind of followed the structure that was layed out here already
    # Since this sensitive route relies on another function - current_user - I would put a flag there to be extra careful. At least
    if username == current_user["username"]:
        if user := get_user(username):
            return user.secret

    # This code runs if someone with a valid token tried to access another user's secret
    raise HTTPException(
        status_code=403,
        detail="Don't spy on other user!"
    )

### Ideas for improvement
# * Deal with more exceptions


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
