from datetime import datetime

from pydantic import BaseModel


class ClientBase(BaseModel):
    id: int
    creator_id: int
    is_active: bool
    uuid: str | None
    key: str
    created: datetime
    last_seen: datetime | None


class ClientCreate(ClientBase):
    pass


class Client(ClientBase):
    key: str | None
    uuid: str | None

    class Config:
        orm_mode = True


class UserBase(BaseModel):
    username: str


class UserDelete(UserBase):
    username: str


class UserCreate(UserBase):
    username: str
    password: str


class User(UserBase):
    id: int
    is_active: bool
    is_super: bool
    created: datetime

    class Config:
        orm_mode = True