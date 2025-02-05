from sqlalchemy import Integer, String, Column, ForeignKey, Enum, DateTime
from sqlalchemy.sql.schema import Column

from .database import Base
# 파일이니깐 .database로 해야함 ./  하면 폴더로 인식함
from sqlalchemy.dialects.postgresql import UUID
import uuid


class Role(str, Enum):
    ADMIN = "ADMIN"
    USER = "USER"

class User(Base):
    __tablename__ = 'User'

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, unique=True, nullable=False)
    name = Column(String, nullable=False, unique=True)
    email = Column(String, unique=True, nullable=False)
    emailVerified = Column(String, nullable=False)
    image = Column(String, nullable=False)
    password = Column(String, nullable=False)
    role = Column(Enum(Role), nullable=False,) #default=Role.USER)
    createdAt = Column(DateTime, nullable=False)
    updatedAt = Column(String, nullable=False)
    # test = Column(Integer, ForeignKey("user,di"))