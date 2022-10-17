from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import jwt

from app import db
from app.constants import Language
from app.schemas import User
from app.security import decode_jwt


def valid_language(language: Optional[str] = "de") -> tuple:
    """Validate if the language is supported by comparing with Language enum."""

    if language not in [lang.value for lang in Language]:
        return ("not supported", language)

    return ("supported", language)


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/task4/token")


def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    """Try to decode a JWT token, retrieve the username and get the user."""

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
    except jwt.JWTError:
        raise credentials_exception

    user = db.get_user(payload["sub"])
    if not user:
        raise credentials_exception

    return user
