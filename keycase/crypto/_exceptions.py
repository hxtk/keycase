"""Exceptions that might occur in the course of cryptogrpahic operations."""


class AuthenticationError(Exception):
    """The decrypted data could not be authenticated."""
