from pydantic import BaseModel, EmailStr
from datetime import datetime

class LoginRequestDto(BaseModel):
    email: str
    password: str

class RegisterRequestDto(LoginRequestDto):
    name: str

    class Config:
        # 암호화된 비밀번호를 직렬화하지 않도록 설정
        from_attributes = True
        #FastAPI에서 ORM 데이터를 응답으로 보낼 때 꼭 사용


# -------------- token --------------
class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username_or_email: str


class TokenBlacklistBase(BaseModel):
    token: str
    expires_at: datetime


class TokenBlacklistCreate(TokenBlacklistBase):
    pass


class TokenBlacklistUpdate(TokenBlacklistBase):
    pass

