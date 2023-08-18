#!/usr/bin/env python3
"""query web server using requests module"""

from auth import Auth
from flask import request

auth = Auth()


def register_user(email: str, password: str) -> None:
    user = auth.register_user(email=EMAIL, password=PASSWD)
    if user:
        return None


def log_in_wrong_password(email: str, password: str) -> None:
    user = auth.valid_login(email=email, password=password)
    if not user or user is False:
        return None


def log_in(email: str, password: str) -> str:
    user = auth.valid_login(email=email, password=password)
    return user


def profile_unlogged() -> None:
    pass


def profile_logged(session_id: str) -> None:
    user = auth.get_user_from_session_id(session_id=session_id)
    if user:
        return None


def log_out(session_id: str) -> None:
    user = auth.get_user_from_session_id(session_id)
    if user is None:
        return None


def reset_password_token(email: str) -> str:
    return auth.get_reset_password_token(email)


def update_password(email: str, reset_token: str, new_password: str) -> None:
    return auth.update_password(reset_token=reset_token, password=new_password)


EMAIL = "guillaume@holberton.io"
PASSWD = "b4l0u"
NEW_PASSWD = "t4rt1fl3tt3"


if __name__ == "__main__":

    register_user(EMAIL, PASSWD)
    log_in_wrong_password(EMAIL, NEW_PASSWD)
    profile_unlogged()
    session_id = log_in(EMAIL, PASSWD)
    profile_logged(session_id)
    log_out(session_id)
    reset_token = reset_password_token(EMAIL)
    update_password(EMAIL, reset_token, NEW_PASSWD)
    log_in(EMAIL, NEW_PASSWD)
