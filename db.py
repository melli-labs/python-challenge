from typing import Optional

from schemas import User
from security import hash_password

text_for_app = {
    "de": {"greeting": "Hallo name_var, ich bin Melli."},
    "en": {"greeting": "Hello name_var, I am Melli."},
    "es": {"greeting": "Hola name_var, soy Melli."},
    "not supported": {
        "greeting": "Hallo name_var, leider spreche ich nicht 'language_var'!"
    },
}

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


def get_user(username: str) -> Optional[User]:
    """Get a user from the database and return as User model."""
    if username not in fake_users_db:
        return
    return User(**fake_users_db[username])
