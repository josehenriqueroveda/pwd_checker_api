from pydantic import BaseModel

class PasswordModel(BaseModel):
    password: str
    leaked: bool | None = None