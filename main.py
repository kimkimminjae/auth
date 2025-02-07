from typing import Annotated
import logging

from dns.dnssectypes import Algorithm
from fastapi import FastAPI, HTTPException, Depends, Response
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

from datetime import datetime, timedelta

from fastcrud import FastCRUD
from sqlalchemy.orm import Session
from fastapi.responses import JSONResponse
from starlette import status

from dto import LoginRequestDto, RegisterRequestDto, Token

from fastapi.params import Depends
from database import get_db
from models import User, Role, TokenBlacklist
from seed import Hasher

from jose import JWTError, jwt
# ruff: noqa
from fastcrud.exceptions.http_exceptions import UnauthorizedException

ALGORITHM = "HS256"

ACCESS_SECRET_KEY = "ab46d6db937993e00cc868ba7b7b8d268f44dc66fe7fdffee1d1f0a447742309"  #openssl rand -hex 32
ACCESS_TOKEN_EXPIRE_MINUTES = 30

REFRESH_SECRET_KEY = "fa43a0ec42dc6c95d5f98b89864bedada72b8bf67f2ca0b076a4bd8291b90b5b"
REFRESH_TOKEN_EXPIRE_MINUTES = 3000


from setting.config import get_settings
oauth_scheme = OAuth2PasswordBearer(tokenUrl="token")

settings = get_settings()

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
    encoded_jwt = jwt.encode(to_encode, ACCESS_SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def create_refresh_token(data: dict, expires_delta: timedelta or None = None):
    """토큰 생성 함수
    https://github.com/jason810496/FastAPI-Vue-OAuth2/blob/main/backend/setting/config.py#L19
    """
    to_encode = data.copy()
    # expire = datetime.utcnow() + timedelta(minutes=settings.access_token_expire_minutes)
    expire = datetime.now() + timedelta(minutes=REFRESH_TOKEN_EXPIRE_MINUTES)

    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode,# settings.refresh_token_secret,
                                 REFRESH_SECRET_KEY, algorithm=ALGORITHM)
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


# https://inpa.tistory.com/entry/WEB-%F0%9F%93%9A-Access-Token-Refresh-Token-%EC%9B%90%EB%A6%AC-feat-JWT
@app.post("/token", response_model=Token)
async def login_for_access_token(response: Response, form_data: OAuth2PasswordRequestForm = Depends()):
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
        data={"username": user.email}, expires_delta=access_token_expires
    )

    refresh_token = create_refresh_token(data={"username": form_data.username})

    response.set_cookie(
        "refresh_token",
        refresh_token,
        httponly=True,
        samesite="strict",
        secure=False,
        # expires=timedelta(settings.refresh_token_expire_minutes),
        expires= datetime.now() + timedelta(minutes=REFRESH_TOKEN_EXPIRE_MINUTES)
    )

    return Token(
        access_token=access_token,
        token_type="Bearer",
    )

# https://www.reddit.com/r/FastAPI/comments/1fed43y/oauth2_example_logout_and_refresh_token/?rdt=53446
#######################################################################################################


@app.post("/logout")
async def logout(response: Response) -> JSONResponse:
    response.delete_cookie("refresh_token") #서버에서는 쿠키 내 refresh_token을 삭제하고
    # return {"message": "Logout successfully"} # fastapi는 dict일 때 자동 직렬화됨 type은 dict
    return JSONResponse(content={"message": "Logout successfully"}) #이후 프론트에서 access_token을 삭제하도록 하면 됨
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
        payload = jwt.decode(token, ACCESS_SECRET_KEY, algorithms=[ALGORITHM])
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
