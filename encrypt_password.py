#!/usr/bin/env python3
"""bcrypt package to perform the hashing (with hashpw)
"""
import bcrypt


def hash_password(password: str) -> bytes:
    """salt
    """
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def is_valid(hashed_password: bytes, password: str) -> bool:
    """cheack pasword
    """
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
