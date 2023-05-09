from sqlalchemy import Boolean, Column, ForeignKey, Integer, String, DateTime, func
from sqlalchemy.orm import relationship

from .database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_active = Column(Boolean, default=True)
    created = Column(DateTime(timezone=True), server_default=func.now())
    is_super = Column(Boolean, default=False)


class Clients(Base):
    __tablename__ = 'clients'

    id = Column(Integer, primary_key=True, unique=True, autoincrement=True, index=True)
    is_active = Column(Boolean, default=True)
    uuid = Column(String, nullable=True)
    key = Column(String, unique=True)
    created = Column(DateTime(timezone=True), server_default=func.now())
    last_seen = Column(DateTime(timezone=True), nullable=True)
    creator_id = Column(Integer, ForeignKey("users.id"))