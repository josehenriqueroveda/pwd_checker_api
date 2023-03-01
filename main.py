import hashlib
import requests
from fastapi import FastAPI
from fastapi.security import HTTPBasic
from logze.recorder.logger import LogRecorder
from logze.models.log import Log
from configparser import ConfigParser
import warnings

warnings.filterwarnings("ignore")


def _logs_db():
    config = ConfigParser()
    config.read(r"./config/config.ini")
    conn = config.get("mongodb", "conn")
    teams_hook = config.get("teams", "webhook")
    return LogRecorder(conn, "logs", "jobs", teams_hook)


def _api_url():
    config = ConfigParser()
    config.read(r"./config/config.ini")
    url = config.get("hibp", "url")
    return url


HIBP_URL = _api_url()

app = FastAPI()
security = HTTPBasic()
recorder = _logs_db()


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
        print(five_chars)
        response = request_data(five_chars)
        return get_password_leaks(response, tail)
    except Exception as e:
        log = Log("PWD_Checker_API", "error", str(e), "check_api_passwords")
        recorder.record_log(log)


@app.get("/")
async def root():
    return {"message": "Hello World"}


@app.post("/check")
async def check_password(password: str):
    try:
        count = check_api_passwords(password)
        if count:
            print(f"{password} was found {count} times.")
            return {"leaked": True, "count": count}
        else:
            print(f"{password} was NOT found.")
            return {"leaked": False, "count": count}
    except Exception as e:
        log = Log("PWD_Checker_API", "error", str(e), "check_password")
        recorder.record_log(log)
