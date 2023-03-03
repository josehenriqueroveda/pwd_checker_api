import os
from fastapi import FastAPI
from fastapi.security import HTTPBasic
from fastapi.middleware.cors import CORSMiddleware
from logze.recorder.logger import LogRecorder
from routers.password_router import pwd_router
from uvicorn import run
import warnings

warnings.filterwarnings("ignore")

app = FastAPI()
security = HTTPBasic()


origins = ["*"]
methods = ["*"]
headers = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=methods,
    allow_headers=headers,
)


app.include_router(router=pwd_router)


@app.get("/")
async def root():
    return {"Developer": "Jose Henrique Roveda", "Version": "1.0.1"}


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8042))
    run(app, host="0.0.0.0", port=port)
