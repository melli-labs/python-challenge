from abc import ABC, abstractmethod
from typing import List, Optional

from fastapi import HTTPException


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

    if is_snake_case(key):
        key_list = key.split("_")
        rest_list = "".join([k.title() for k in key_list[1:]])
        return f"{key_list[0]}{rest_list}"
    else:
        raise HTTPException(
            status_code=422,
            detail="Ups, das wird nicht funktionieren, da der von dir bereitgestellte String nicht der Snake Case Convention folgt.",
        )


class Action(ABC):
    """Interface like class for all actions."""

    @abstractmethod
    def execute(self, action: str, user_friends: List[str], user: Optional[str] = None):
        pass


class Call(Action):
    """Action for calling someone."""

    intent = "call"

    def execute(self, action: str, user_friends: List[str], user: Optional[str] = None):
        """Call someone by checking on the user and the friend."""

        if not user:
            raise HTTPException(
                status_code=409,
                detail="This error is unexpected. Please make sure to provide an existing username.",
            )

        for u_f in user_friends:
            if u_f in action:
                return f"🤙 Calling {u_f} ..."

        return f"{user}, I can't find this person in your contacts."


class Reminder(Action):
    """Action for setting a reminder."""

    intent = "remind"

    def execute(self, action: str, user_friends: List[str], user: Optional[str] = None):
        """Remind by doing something."""

        return "🔔 Alright, I will remind you!"


class Timer(Action):
    """Action for setting a timer."""

    intent = "timer"

    def execute(self, action: str, user_friends: List[str], user: Optional[str] = None):
        """Stop time by doing something."""

        return "⏰ Alright, the timer is set!"


class Unknown(Action):
    """Action if we don't have the appropriate task at hand."""

    intent = "unknown"

    def execute(self, action: str, user_friends: List[str], user: Optional[str] = None):
        """Stop time by doing something."""

        return "👀 Sorry , but I can't help with that!"


call_action = Call()
reminder_action = Reminder()
timer_action = Timer()
unknown_action = Unknown()


class ActionHandler:
    """Handles to executed the appropriate action."""

    actions = [call_action, reminder_action, timer_action, unknown_action]

    def __init__(self) -> None:
        self.friends = {
            "Matthias": ["Sahar", "Franziska", "Hans"],
            "Stefan": ["Felix", "Ben", "Philip"],
        }

    def decide(self, intent: str):
        """Decide on which action by checking on the intent."""
        for action in self.actions:
            if intent == action.intent:
                return action


class Intention:
    def __init__(self) -> None:
        pass

    def recognize(self, text: str):
        """Recognize an intent by checking for lower cased words in the text of the user."""
        if "call" in text.lower():
            return "call"
        if "remind" in text.lower():
            return "remind"
        if "timer" in text.lower():
            return "timer"

        return "unknown"


intention = Intention()

action_handler = ActionHandler()
