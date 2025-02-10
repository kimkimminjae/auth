from datetime import datetime

from sqlalchemy import String, text, func, DateTime, Enum as SQLAlchemyEnum
from enum import Enum
from sqlalchemy.sql.schema import Column
from setting.database import Base # 파일이니깐 .database로 해야함 ./  하면 폴더로 인식함
from sqlalchemy.dialects.postgresql import UUID
import uuid
from sqlalchemy.orm import Mapped, mapped_column

class Role(str, Enum):
    ADMIN = "ADMIN"
    USER = "USER"

class User(Base):
    __tablename__ = 'User'

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, unique=True, nullable=False)
    # id = Column(Integer, primary_key=True, autoincrement=True, unique=True, nullable=False)

    name = Column(String, nullable=False, unique=True)
    email = Column(String, unique=True, nullable=False)

    emailVerified = Column(DateTime, nullable=False) # email이
    image = Column(String, nullable=True)

    password = Column(String, nullable=False)

    role = Column(SQLAlchemyEnum(Role), nullable=False, default=Role.USER)
    createdAt = Column(DateTime, nullable=False, server_default=text("CURRENT_TIMESTAMP")) # sql에서 지정한 타임스탬프 그대로 사용
    updatedAt = Column(DateTime, nullable=False, default=func.now(), onupdate=func.now())  # 현재 타임스탬프 자동 생성되며 업데이터 될 때마다 자동 업데이트
    # 만약 updateAt도 sql에 미리 지정하려면 ON UPDATE CURRENT_TIMESTAMP 추가하고

    # default값을 지정하지 않고  updated_at = Column(DateTime, server_default=text("CURRENT_TIMESTAMP"), server_onupdate=text("CURRENT_TIMESTAMP")) 이렇게 만들면 된다,
    # test = Column(Integer, ForeignKey("user,di"))

    # @validator("email")
    # https://datamoney.tistory.com/361
    # def email_validator(cls, email):
    #     if not email:
    #         raise ValueError("이메일은 필수입니다.")
    #     return email

# -------------- token --------------


class TokenBlacklist(Base):
    __tablename__ = "TokenBlacklist"

    id: Mapped[int] = mapped_column("id", autoincrement=True, nullable=False, unique=True, primary_key=True)
    token: Mapped[str] = mapped_column(String, unique=True, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime)


