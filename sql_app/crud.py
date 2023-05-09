import random
import string

from fastapi import HTTPException
from passlib.context import CryptContext
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from starlette import status

from . import models, schemas


def get_user(db: Session, user_id: int):
    return db.query(models.User).filter(models.User.id == user_id).first()


def get_user_by_username(db: Session, username: str):
    return db.query(models.User).filter(models.User.username == username).first()


def get_users(db: Session, skip: int = 0, limit: int = 100):
    return db.query(models.User).offset(skip).limit(limit).all()


def delete_user(db: Session, user: schemas.UserDelete):
    try:
        db.query(models.User).filter(models.User.username == user.username).delete()
        db.commit()
        return True
    except Exception:
        return False


def create_user(db: Session, user: schemas.UserCreate, is_super=False):
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    hashed_password = pwd_context.hash(user.password)
    db_user = models.User(username=user.username, hashed_password=hashed_password, is_super=is_super)
    db.add(db_user)
    try:
        db.commit()
        db.refresh(db_user)
        return db_user
    except IntegrityError:
        credentials_exception = HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User already created",
            headers={"WWW-Authenticate": "Bearer"},
        )
        raise credentials_exception


def get_client(db: Session, key: str, uuid: str = None):
    if key and uuid:
        return db.query(models.Clients).filter((models.Clients.key == key) &
                                               (models.Clients.uuid == uuid)).first()
    elif key:
        return db.query(models.Clients).filter(models.Clients.key == key).first()
    else:
        return db.query(models.Clients).filter(models.Clients.uuid == uuid).first()


def get_clients(db: Session, skip: int = 0, limit: int = 100):
    return db.query(models.Clients).offset(skip).limit(limit).all()


def delete_client(db: Session, client_id: int):
    try:
        db.query(models.Clients).filter(models.Clients.id == client_id).delete()
        db.commit()
        return True
    except Exception:
        return False


def create_client(db: Session, user_id: int):
    key = ''.join((random.choice(string.ascii_letters.upper()) for x in range(16)))
    db_item = models.Clients(creator_id=user_id, key=key)
    db.add(db_item)
    db.commit()
    db.refresh(db_item)
    return db_item
