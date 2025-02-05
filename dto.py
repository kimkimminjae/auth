from pydantic import BaseModel, EmailStr

class RegisterRequestDto(BaseModel):
    name: str
    email: EmailStr
    password: str

    class Config:
        # 암호화된 비밀번호를 직렬화하지 않도록 설정
        orm_mode = True

