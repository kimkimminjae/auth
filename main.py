from typing import Annotated
import logging
from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer

from datetime import datetime

from sqlalchemy.orm import Session
from fastapi.responses import JSONResponse

from dto import LoginRequestDto, RegisterRequestDto

from fastapi.params import Depends
from database import get_db
from models import User, Role
from seed import Hasher
app = FastAPI()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@app.post("/register/")
def register(user: RegisterRequestDto, db: Session = Depends(get_db)) -> JSONResponse:
    try:
        is_stored_user = db.query(User).filter(User.email == user.email).first()
        if is_stored_user:
            raise HTTPException(status_code=400, detail="Email already registered")

        new_user = User(
            name=user.name,
            email=str(user.email),
            password=Hasher.get_password_hash(user.password),
            emailVerified=datetime.now(),
            role=Role.USER
        )
        db.add(new_user)
        db.commit()
        db.refresh(new_user)

        print(new_user)

        return JSONResponse(
            content={"message": "User registered successfully"},
            status_code=200,
            headers={"X-Custom-Header": "MyValue"},
            media_type="application/json"
        )
    except Exception as e:
        logger.error(f"Error in register endpoint: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error")

    # return {"message": "Hello, FastAPI!"}  # fastapi는 dict일 때 자동 직렬화됨


@app.post("/login/")
async def login(user: LoginRequestDto, db: Session = Depends(get_db)):
    # DB에서 사용자 조회
    stored_user = db.query(User).filter(User.email == user.email).first()
    if not stored_user:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    # 비밀번호 검증
    if not Hasher.verify_password(user.password, stored_user.password):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    return {"msg": "Login successful"}


@app.get("/")
async def root():
    return {"message": "Hello World"}


@app.get("/hello/{name}")
async def say_hello(name: str):
    return {"message": f"Hello {name}"}


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

@app.get("/items/")
async def read_items(token: Annotated[str, Depends(oauth2_scheme)]):
    return {"token": token}
