from datetime import datetime, timedelta
from functools import partial
from pathlib import Path
from typing import Any, Tuple

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from tomlkit.api import parse

import dep
import services
from db import get_user, text_for_app
from schemas import ActionRequest, ActionResponse, Token, User
from security import encode_jwt, verify_password

app = FastAPI(
    title="Melli Hiring Challenge 👩‍💻",
    description="Help Melli 👩 to fix our tests and get a job interview 💼🎙️!",
)


"""
Task 1 - Warmup
"""


@app.get("/task1/greet/{name}", tags=["Task 1"], summary="👋🇩🇪🇬🇧🇪🇸")
async def task1_greet(
    name: str, language: Tuple[str, str] = Depends(dep.valid_language)
) -> str:
    """Greet somebody in German, English or Spanish!"""
    if language[0] == "not supported":
        return (
            text_for_app[language[0]]["greeting"]
            .replace("name_var", name)
            .replace("language_var", language[1])
        )

    if language[0] == "supported":
        return text_for_app[language[1]]["greeting"].replace("name_var", name)


"""
Task 2 - snake_case to cameCase
"""


@app.post("/task2/camelize", tags=["Task 2"], summary="🐍➡️🐪")
async def task2_camelize(data: dict[str, Any]) -> dict[str, Any]:
    """Takes a JSON object and transfroms all keys from snake_case to camelCase."""
    return {services.camelize(key): value for key, value in data.items()}


"""
Task 3 - Handle User Actions
"""


@app.post("/task3/action", tags=["Task 3"], summary="🤌", response_model=ActionResponse)
def task3_action(request: ActionRequest):
    """Accepts an action request, recognizes its intent and forwards it to the corresponding action handler."""
    # tip: you have to use the response model above and also might change the signature
    #      of the action handlers
    # Write your code below
    user = request.username

    if user not in services.action_handler.friends.keys():
        return ActionResponse(
            message=f"Hi {user}, I don't know you yet. But I would love to meet you!"
        )

    intent = services.intention.recognize(request.action)

    user_friends = services.action_handler.friends[user]

    action = services.action_handler.decide(intent)

    return ActionResponse(message=action.execute(request.action, user_friends, user))


"""
Task 4 - Security
"""


@app.post("/task4/token", response_model=Token, summary="🔒", tags=["Task 4"])
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """Allows registered users to obtain a bearer token."""
    # fixme 🔨, at the moment we allow everybody to obtain a token
    # this is probably not very secure 🛡️ ...
    # tip: check the verify_password above
    # Write your code below
    user = get_user(form_data.username)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )

    if not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )

    payload = {
        "sub": form_data.username,
        "exp": datetime.utcnow() + timedelta(minutes=30),
    }

    jwt_token = {
        "access_token": encode_jwt(payload),
        "token_type": "bearer",
    }

    return Token(**jwt_token)


@app.get("/task4/users/{username}/secret", summary="🤫", tags=["Task 4"])
async def read_user_secret(
    username: str, current_user: User = Depends(dep.get_current_user)
):
    """Read a user's secret."""
    # uppps 🤭 maybe we should check if the requested secret actually belongs to the user
    # Write your code below

    if current_user != get_user(username):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Don't spy on other user!",
        )

    return current_user.secret


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
