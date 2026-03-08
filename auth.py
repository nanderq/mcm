import getpass
import hashlib
import hmac
import os
import secrets
import sys
import threading
import time
from collections import defaultdict
from dataclasses import dataclass
from typing import Any

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from fastapi import HTTPException, Request

DEFAULT_SESSION_TTL_SECONDS = 43200
FAILED_LOGIN_LIMIT = 5
FAILED_LOGIN_WINDOW_SECONDS = 900
MIN_SESSION_SECRET_LENGTH = 32
DEFAULT_USERNAME = "admin"
DEFAULT_PASSWORD = "admin"
COOKIE_NAME = "mcm_session"
SESSION_USERNAME_KEY = "username"
SESSION_AUTHENTICATED_KEY = "authenticated"
SESSION_AUTH_VERSION_KEY = "auth_version"
SESSION_CSRF_TOKEN_KEY = "csrf_token"
SESSION_ISSUED_AT_KEY = "issued_at"
PLACEHOLDER_SESSION_SECRET = "dev-placeholder-session-secret-not-for-production"


@dataclass(frozen=True)
class AuthSettings:
    username: str
    password_hash: str
    session_secret: str
    cookie_secure: bool
    session_ttl_seconds: int


class AuthConfigurationError(RuntimeError):
    pass


class CsrfError(RuntimeError):
    pass


class LoginRateLimitError(RuntimeError):
    def __init__(self, retry_after: int) -> None:
        super().__init__("Too many login attempts. Try again later.")
        self.retry_after = retry_after


_password_hasher = PasswordHasher()
_dummy_password_hash = _password_hasher.hash("mcm-dummy-password")
_default_password_hash = _password_hasher.hash(DEFAULT_PASSWORD)


def _parse_bool(value: str | None, *, default: bool) -> bool:
    if value is None:
        return default

    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise AuthConfigurationError("MCM_COOKIE_SECURE must be a boolean value.")


def _parse_ttl(value: str | None) -> int:
    if value is None or not value.strip():
        return DEFAULT_SESSION_TTL_SECONDS

    try:
        ttl = int(value)
    except ValueError as exc:
        raise AuthConfigurationError("MCM_SESSION_TTL_SECONDS must be an integer.") from exc

    if ttl <= 0:
        raise AuthConfigurationError("MCM_SESSION_TTL_SECONDS must be greater than zero.")
    return ttl


def load_auth_settings(*, validate_required: bool = True) -> AuthSettings:
    username = (os.getenv("MCM_AUTH_USERNAME") or DEFAULT_USERNAME).strip()
    password_hash = (os.getenv("MCM_AUTH_PASSWORD_HASH") or _default_password_hash).strip()
    session_secret = (os.getenv("MCM_SESSION_SECRET") or PLACEHOLDER_SESSION_SECRET).strip()
    cookie_secure = _parse_bool(os.getenv("MCM_COOKIE_SECURE"), default=True)
    session_ttl_seconds = _parse_ttl(os.getenv("MCM_SESSION_TTL_SECONDS"))

    if validate_required:
        if len(session_secret) < MIN_SESSION_SECRET_LENGTH:
            raise AuthConfigurationError(
                f"MCM_SESSION_SECRET must be at least {MIN_SESSION_SECRET_LENGTH} characters."
            )

    return AuthSettings(
        username=username,
        password_hash=password_hash,
        session_secret=session_secret,
        cookie_secure=cookie_secure,
        session_ttl_seconds=session_ttl_seconds,
    )


def build_auth_version(settings: AuthSettings) -> str:
    return hashlib.sha256(settings.password_hash.encode("utf-8")).hexdigest()


def validate_auth_configuration() -> AuthSettings:
    settings = load_auth_settings(validate_required=True)
    try:
        _password_hasher.verify(settings.password_hash, "configuration-check")
    except VerificationError:
        pass
    except InvalidHashError as exc:
        raise AuthConfigurationError("MCM_AUTH_PASSWORD_HASH must be a valid Argon2 hash.") from exc
    return settings


def _clear_session(request: Request) -> None:
    request.session.clear()


def is_authenticated(request: Request) -> bool:
    settings = load_auth_settings(validate_required=False)
    session = request.session

    try:
        authenticated = session[SESSION_AUTHENTICATED_KEY]
        username = session[SESSION_USERNAME_KEY]
        auth_version = session[SESSION_AUTH_VERSION_KEY]
        csrf_token = session[SESSION_CSRF_TOKEN_KEY]
        issued_at = float(session[SESSION_ISSUED_AT_KEY])
    except (KeyError, TypeError, ValueError):
        _clear_session(request)
        return False

    if authenticated is not True:
        _clear_session(request)
        return False

    if not isinstance(username, str) or not hmac.compare_digest(username, settings.username):
        _clear_session(request)
        return False

    expected_auth_version = build_auth_version(settings)
    if not isinstance(auth_version, str) or not hmac.compare_digest(auth_version, expected_auth_version):
        _clear_session(request)
        return False

    if not isinstance(csrf_token, str) or not csrf_token:
        _clear_session(request)
        return False

    if (time.time() - issued_at) > settings.session_ttl_seconds:
        _clear_session(request)
        return False

    return True


def login_user(request: Request) -> None:
    settings = load_auth_settings(validate_required=True)
    request.session.clear()
    request.session.update(
        {
            SESSION_AUTHENTICATED_KEY: True,
            SESSION_USERNAME_KEY: settings.username,
            SESSION_AUTH_VERSION_KEY: build_auth_version(settings),
            SESSION_CSRF_TOKEN_KEY: secrets.token_urlsafe(32),
            SESSION_ISSUED_AT_KEY: int(time.time()),
        }
    )


def logout_user(request: Request) -> None:
    _clear_session(request)


def get_csrf_token(request: Request) -> str:
    token = request.session.get(SESSION_CSRF_TOKEN_KEY)
    if isinstance(token, str) and token:
        return token

    token = secrets.token_urlsafe(32)
    request.session[SESSION_CSRF_TOKEN_KEY] = token
    return token


async def require_csrf(request: Request) -> None:
    expected = request.session.get(SESSION_CSRF_TOKEN_KEY)
    if not isinstance(expected, str) or not expected:
        raise CsrfError("Invalid CSRF token")

    candidate = request.headers.get("X-CSRF-Token")
    if not candidate and request.method.upper() in {"POST", "PUT", "PATCH", "DELETE"}:
        content_type = request.headers.get("content-type", "")
        if "application/x-www-form-urlencoded" in content_type or "multipart/form-data" in content_type:
            form = await request.form()
            form_value = form.get("csrf_token")
            if isinstance(form_value, str):
                candidate = form_value

    if not candidate or not hmac.compare_digest(candidate, expected):
        raise CsrfError("Invalid CSRF token")


def verify_credentials(username: str, password: str) -> bool:
    settings = load_auth_settings(validate_required=True)
    username_match = hmac.compare_digest(username, settings.username)
    target_hash = settings.password_hash if username_match else _dummy_password_hash

    try:
        password_match = _password_hasher.verify(target_hash, password)
    except (InvalidHashError, VerificationError):
        password_match = False

    return username_match and password_match


class LoginAttemptTracker:
    def __init__(self) -> None:
        self._attempts: dict[str, list[float]] = defaultdict(list)
        self._lock = threading.Lock()

    def _prune(self, client_ip: str, now: float) -> list[float]:
        attempts = [
            timestamp
            for timestamp in self._attempts.get(client_ip, [])
            if (now - timestamp) < FAILED_LOGIN_WINDOW_SECONDS
        ]
        if attempts:
            self._attempts[client_ip] = attempts
        else:
            self._attempts.pop(client_ip, None)
        return attempts

    def check(self, client_ip: str) -> None:
        now = time.time()
        with self._lock:
            attempts = self._prune(client_ip, now)
            if len(attempts) >= FAILED_LOGIN_LIMIT:
                retry_after = max(1, int(FAILED_LOGIN_WINDOW_SECONDS - (now - attempts[0])))
                raise LoginRateLimitError(retry_after)

    def record_failure(self, client_ip: str) -> None:
        now = time.time()
        with self._lock:
            attempts = self._prune(client_ip, now)
            attempts.append(now)
            self._attempts[client_ip] = attempts

    def clear(self, client_ip: str) -> None:
        with self._lock:
            self._attempts.pop(client_ip, None)

    def reset(self) -> None:
        with self._lock:
            self._attempts.clear()


login_attempt_tracker = LoginAttemptTracker()


def get_client_ip(request: Request) -> str:
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        return forwarded_for.split(",", 1)[0].strip()
    client = request.client
    return client.host if client and client.host else "unknown"


def enforce_login_rate_limit(request: Request) -> None:
    login_attempt_tracker.check(get_client_ip(request))


def record_login_failure(request: Request) -> None:
    login_attempt_tracker.record_failure(get_client_ip(request))


def clear_login_failures(request: Request) -> None:
    login_attempt_tracker.clear(get_client_ip(request))


def reset_login_attempts() -> None:
    login_attempt_tracker.reset()


def hash_password_cli() -> None:
    if len(sys.argv) > 1:
        password = sys.argv[1]
    else:
        password = getpass.getpass("Password: ")

    if not password:
        raise SystemExit("Password cannot be empty.")

    sys.stdout.write(f"{_password_hasher.hash(password)}\n")


def csrf_http_exception() -> HTTPException:
    return HTTPException(status_code=403, detail="Invalid CSRF token")
