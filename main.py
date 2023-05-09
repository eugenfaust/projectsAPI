from datetime import datetime, timedelta
from os import getenv
from typing import Annotated

from cryptography.fernet import Fernet, InvalidToken
from fastapi import Depends, FastAPI, HTTPException, status, Query
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel

# to get a string like this run:
# openssl rand -hex 32
from sql_app.schemas import User
from sqlalchemy.orm import Session

from sql_app import models, crud, schemas
from sql_app.database import engine, SessionLocal
from dotenv import load_dotenv

load_dotenv()
SECRET_KEY = getenv("HASH_SECRET")
CLIENT_SECRET_KEY = getenv("CLIENT_SECRET")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(getenv("ACCESS_TOKEN_EXPIRE_MINUTES"))


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str | None = None


models.Base.metadata.create_all(bind=engine)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Create default user
try:
    crud.create_user(next(get_db()), schemas.UserCreate(username="admin", password="12345"), is_super=True)
except HTTPException:
    pass


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def authenticate_user(username: str, password: str, db: Session = Depends(get_db)) -> models.User | bool:
    user = crud.get_user_by_username(db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)], db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = crud.get_user_by_username(db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(
        current_user: Annotated[User, Depends(get_current_user)]
):
    if not current_user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


@app.post("/token", response_model=Token)
async def login_for_access_token(
        form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
        db: Session = Depends(get_db)):
    user = authenticate_user(form_data.username, form_data.password, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/users/me/", response_model=User)
async def read_users_me(
        current_user: Annotated[User, Depends(get_current_active_user)]
):
    return current_user


@app.post("/users/create/", response_model=User)
async def create_user(
        user: schemas.UserCreate,
        current_user: Annotated[User, Depends(get_current_active_user)],
        db: Session = Depends(get_db),
):
    if not current_user.is_super:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="You have no rights",
            headers={"WWW-Authenticate": "Bearer"}
        )
    user = crud.create_user(db, user)
    return user


@app.post("/users/delete/")
async def delete_user(
        user: schemas.UserDelete,
        current_user: Annotated[User, Depends(get_current_active_user)],
        db: Session = Depends(get_db)
):
    if not current_user.is_super:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="You have no rights",
            headers={"WWW-Authenticate": "Bearer"}
        )
    user = crud.delete_user(db, user)
    if user:
        return {"status": "success"}
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Error while deleting",
            headers={"WWW-Authenticate": "Bearer"}
        )


@app.get("/clients/")
async def read_clients(
        current_user: Annotated[User, Depends(get_current_active_user)],
        db: Session = Depends(get_db)
):
    clients = crud.get_clients(db)
    return clients


@app.post("/clients/create/", response_model=schemas.Client)
async def create_client(
        current_user: Annotated[User, Depends(get_current_active_user)],
        db: Session = Depends(get_db)
):
    client = crud.create_client(db, current_user.id)
    return client


@app.delete("/clients/delete/{client_id}")
async def delete_client(
        client_id: int,
        current_user: Annotated[User, Depends(get_current_active_user)],
        db: Session = Depends(get_db)
):
    client = crud.delete_client(db, client_id)
    if client:
        return {"status": "success"}
    else:
        return {"status": "false"}


class Key(BaseModel):
    key: str = Query(min_length=16, max_length=16)
    token: str = Query(min_length=140, max_length=200)


@app.post("/check/")
async def check_client(key: Key,
                       db: Session = Depends(get_db)):
    client: models.Clients = crud.get_client(db, key.key, key.token)
    fernet = Fernet(CLIENT_SECRET_KEY)
    try:
        uuid = fernet.decrypt(key.token).decode('utf-8')
    except InvalidToken:
        return fernet.encrypt("result is false".encode()).decode()
    if client:
        if client.is_active:
            if not client.uuid:
                await client.update(uuid=uuid).apply()
                return fernet.encrypt("result is true".encode()).decode()
            elif client.uuid == uuid:
                return fernet.encrypt("result is true".encode()).decode()
            return fernet.encrypt("result is false".encode()).decode()
    return fernet.encrypt("result is false".encode()).decode()
