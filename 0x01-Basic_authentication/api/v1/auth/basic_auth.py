#!/usr/bin/env python3
"""class that provides basic authentication
"""
from api.v1.auth.auth import Auth
from typing import TypeVar
import base64


class BasicAuth(Auth):
    """provides basic authentivation to API"""
    def extract_base64_authorization_header(self,
                                            authorization_header: str) -> str:
        if authorization_header is None:
            return None
        if not isinstance(authorization_header, str):
            return None
        if not authorization_header.startswith('Basic '):
            return None
        return authorization_header.split(' ')[-1]

    def decode_base64_authorization_header(
            self, base64_authorization_header: str) -> str:
        if base64_authorization_header is None:
            return None
        if not isinstance(base64_authorization_header, str):
            return None
        try:
            data = base64_authorization_header.encode('utf-8')
            decoded = base64.b64decode(data)
            return decoded.decode('utf-8')
        except Exception:
            return None

    def extract_user_credentials(
            self, decoded_base64_authorization_header: str) -> (str, str):
        if decoded_base64_authorization_header is None:
            return (None, None)
        if not isinstance(decoded_base64_authorization_header, str):
            return (None, None)
        if ':' not in decoded_base64_authorization_header:
            return (None, None)
        user, passw = decoded_base64_authorization_header.split(':')
        return (user, passw)

    def user_object_from_credentials(
            self, user_email: str, user_pwd: str) -> TypeVar('User'):
        if user_email is None or not isinstance(user_email, str):
            return None
        if user_pwd is None or not isinstance(user_pwd, str):
            return None
        try:
            user = User.search({"email": user_email})
            if not user or user == []:
                return None
            for use in user:
                if use.is_valid_password(user_pwd):
                    return use
            return None
        except Exception as e:
            return None

    def current_user(self, request=None) -> TypeVar('User'):
        header = self.authorization_header(request)
        if header:
            author = self.extract_base64_authorization_header(header)
            if author:
                decode = self.decode_base64_authorization_header(author)
                if decode:
                    email, passw = self.extract_user_credentials(decode)
                    if email:
                        return self.user_object_from_credentials(email, passw)

        return
