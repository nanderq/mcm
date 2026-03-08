import os

from argon2 import PasswordHasher


TEST_AUTH_USERNAME = "admin"
TEST_AUTH_PASSWORD = "test-password"
TEST_SESSION_SECRET = "test-session-secret-with-32-plus-characters"

os.environ.setdefault("MCM_AUTH_USERNAME", TEST_AUTH_USERNAME)
os.environ.setdefault("MCM_AUTH_PASSWORD_HASH", PasswordHasher().hash(TEST_AUTH_PASSWORD))
os.environ.setdefault("MCM_SESSION_SECRET", TEST_SESSION_SECRET)
os.environ.setdefault("MCM_COOKIE_SECURE", "false")
os.environ.setdefault("MCM_AUTH_TEST_PASSWORD", TEST_AUTH_PASSWORD)
