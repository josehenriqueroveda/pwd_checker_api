import hashlib
import requests
from fastapi import APIRouter
from classes.PasswordModel import PasswordModel
from logze.models.log import Log
from logze.recorder.logger import LogRecorder
from configparser import ConfigParser


def _api_url():
    config = ConfigParser()
    config.read(r"./config/config.ini")
    url = config.get("hibp", "url")
    return url


def _logs_db():
    config = ConfigParser()
    config.read(r"./config/config.ini")
    conn = config.get("mongodb", "conn")
    teams_hook = config.get("teams", "webhook")
    return LogRecorder(conn, "logs", "jobs", teams_hook)


pwd_router = APIRouter()
HIBP_URL = _api_url()
recorder = _logs_db()


def password_strength(password):
    if len(password) < 8:
        return False

    has_uppercase = any(char.isupper() for char in password)
    has_lowercase = any(char.islower() for char in password)
    has_digit = any(char.isdigit() for char in password)
    has_special_char = any(char in "!@#$%^&*()_+-=[]{}|;:,.<>/?" for char in password)

    return has_uppercase and has_lowercase and has_digit and has_special_char


def request_data(query_char):
    try:
        url = HIBP_URL + query_char
        res = requests.get(url)
        if res.status_code != 200:
            raise RuntimeError(
                f"Error: {res.status_code} - Check the API docs and try again"
            )
        return res
    except Exception as e:
        log = Log("PWD_Checker_API", "error", str(e), "request_data")
        recorder.record_log(log)


def get_password_leaks(hashes, hash_tail):
    hashes = (line.split(":") for line in hashes.text.splitlines())
    for h, leaks in hashes:
        if h == hash_tail:
            return leaks
    return 0


def check_api_passwords(password):
    try:
        sha1password = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        five_chars, tail = sha1password[:5], sha1password[5:]
        response = request_data(five_chars)
        return get_password_leaks(response, tail)
    except Exception as e:
        log = Log("PWD_Checker_API", "error", str(e), "check_api_passwords")
        recorder.record_log(log)


@pwd_router.post(
    "/check",
    tags=["Security"],
    description="Checks the password strength and if it was found in any data leak.",
)
async def check_password(pm: PasswordModel):
    try:
        pm = dict(pm)
        pwd = pm["password"]
        count = check_api_passwords(pwd)
        strength = password_strength(pwd)
        if count == 0:
            leaked = False
        elif count > 0:
            leaked = True

        if strength:
            return {"leaked": leaked, "count": count, "strength": True}
        else:
            return {"leaked": leaked, "count": 0, "strength": False}
    except Exception as e:
        log = Log("PWD_Checker_API", "error", str(e), "check_password")
        recorder.record_log(log)
