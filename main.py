from typing import Annotated
import logging

from dns.dnssectypes import Algorithm
from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

from datetime import datetime, timedelta

from sqlalchemy.orm import Session
from fastapi.responses import JSONResponse
from starlette import status

from dto import LoginRequestDto, RegisterRequestDto, Token

from fastapi.params import Depends
from database import get_db
from models import User, Role
from seed import Hasher

from jose import JWTError, jwt

SECRET_KEY = "ab46d6db937993e00cc868ba7b7b8d268f44dc66fe7fdffee1d1f0a447742309"  #openssl rand -hex 32
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

oauth_scheme = OAuth2PasswordBearer(tokenUrl="token")

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


#########################################################################################################


def create_access_token(data: dict, expires_delta: timedelta or None = None):
    """토큰 생성 함수"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now() + expires_delta
    else:
        expire = datetime.now() + timedelta(minutes=15)

    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def authenticate_user(username: str, password: str, db: Session = Depends(get_db)):
    """유저 인증 함수"""
    #OAuth2PasswordRequestForm 는 기본적으로 username, password 필드를 가지고 있으므로 username 명으로 받고 email로 매칭 또 1) 커스텀 폼 클래스로 email 필드 추가하기 2)OAuth2PasswordRequestForm 확장하기 (scopes 등 유지 가능) 방법도 있음
    user = db.query(User).filter(User.email == username).first()
    if not user:
        return False
    if not Hasher.verify_password(password, user.password):
        return False
    return user


@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    """login -> 유저인증 -> 토큰 생성 -> 토큰 반환"""

    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


#######################################################################################################
#프로트엔드에서 jwt 토큰을 Authorization 헤더에 포함시켜 /users/me 엔드포인트에 요청을 보내면 된다.
def get_current_user(token: str = Depends(oauth_scheme), db: Session = Depends(get_db)):
    """현재 사용자 정보(토큰) 확인"""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = db.query(User).filter(User.email == email).first()
    if user is None:
        raise credentials_exception
    return user


@app.get("/users/me")
async def read_users_me(current_user: User = Depends(get_current_user)):
    """https://databoom.tistory.com/entry/FastAPI-JWT-%EA%B8%B0%EB%B0%98-%EC%9D%B8%EC%A6%9D-6"""
    return {"current_user": current_user}


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
