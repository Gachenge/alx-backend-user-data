#!/usr/bin/env python3
"""hash a password"""
import bcrypt
from db import DB
from sqlalchemy.orm.exc import NoResultFound
from typing import Union
from user import User
from uuid import uuid4


def _hash_password(password):
    """hash a user password"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def _generate_uuid():
    """generate unique id"""
    return str(uuid4())


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        """_summary_
        """
        self._db = DB()

    def register_user(self, email: str, password: str) -> Union[User, None]:
        """register a new user"""
        try:
            user = self._db.find_user_by(email=email)
            if user:
                raise ValueError(f"User {email} already exists")
        except NoResultFound:
            return self._db.add_user(email, _hash_password(password))

    def valid_login(self, email: str, password: str) -> bool:
        """check if the user is valid"""
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            return False
        return bcrypt.checkpw(password.encode('utf-8'), user.hashed_password)

    def create_session(self, email: str) -> str:
        """create a session on login"""
        try:
            user = self._db.find_user_by(email=email)
            user.session_id = _generate_uuid()
            return user.session_id
        except Exception:
            pass

    def get_user_from_session_id(self, session_id: str) -> Union[User, None]:
        """get current user"""
        if session_id is None:
            return None
        try:
            user = self._db.find_user_by(session_id=session_id)
        except NoResultFound:
            return None
        else:
            return user

    def destroy_session(self, user_id: int) -> None:
        """destroy current session"""
        try:
            user = self._db.find_user_by(id=user_id)
        except NoResultFound:
            return None
        else:
            user.session_id = None
            return None

    def get_reset_password_token(self, email: str) -> str:
        """_summary_

        Args:
            email (str): _description_

        Raises:
            ValueError: _description_

        Returns:
            str: _description_
        """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            raise ValueError
        else:
            user.reset_token = _generate_uuid()
            return user.reset_token

    def update_password(self, reset_token: str, password: str) -> None:
        """_summary_

        Args:
            reset_token (str): _description_
            password (str): _description_

        Raises:
            ValueError: _description_
        """
        try:
            user = self._db.find_user_by(reset_token=user.reset_token)
        except NoResultFound:
            raise ValueError
        else:
            user.hashed_password = _hash_password(password)
            user.reset_token = None
