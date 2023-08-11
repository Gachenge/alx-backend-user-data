#!/usr/bin/env python3
""" class that handles API authentication """

from flask import request
from typing import List, TypeVar


class Auth:
    """ to handle API authentication """
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """ check authentication"""
        if path is None or excluded_paths is None or len(excluded_paths) == 0:
            return True
        if path in excluded_paths:
            return False
        for excluded in excluded_paths:
            if excluded.startswith(path):
                return False
            elif path.startswith(excluded):
                return False
            elif excluded[-1] == '*':
                if path.startswith(excluded[:-1]):
                    return False
        return True

    def authorization_header(self, request=None) -> str:
        """return authorisation header from request"""
        if request is None:
            return None
        header = request.headers.get('Authorization')
        if header is None:
            return None
        return header


    def current_user(self, request=None) -> TypeVar('User'):
        """return current user from request"""
        return None
