from enum import Enum

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