from datetime import timedelta, datetime

from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from sqlalchemy.orm import Session
from fastapi import Depends, HTTPException
from starlette import status

from auth.utils.crud_token_blacklist import crud_token_blacklist
from setting.database import get_db
from auth.model.auth_model import User
from auth.model.auth_shemas import TokenBlacklistCreate, TokenData
from passlib.context import CryptContext

oauth_scheme = OAuth2PasswordBearer(tokenUrl="token")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

ALGORITHM = "HS256"

SECRET_KEY = "ab46d6db937993e00cc868ba7b7b8d268f44dc66fe7fdffee1d1f0a447742309"  #openssl rand -hex 32
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_MINUTES = 3000


class Hasher:

    @staticmethod
    def get_password_hash(password):
        return pwd_context.hash(password)

    @staticmethod
    def verify_password(plain_password, hashed_password):
        return pwd_context.verify(plain_password, hashed_password)

def authenticate_user(username_or_email: str, password: str, db: Session = Depends(get_db)):
    """유저 인증 함수"""
    #OAuth2PasswordRequestForm 는 기본적으로 username, password 필드를 가지고 있으므로 username 명으로 받고 email로 매칭 또 1) 커스텀 폼 클래스로 email 필드 추가하기 2)OAuth2PasswordRequestForm 확장하기 (scopes 등 유지 가능) 방법도 있음
    user = db.query(User).filter(User.email == username_or_email).first()
    if not user:
        return False
    if not Hasher.verify_password(password, user.password):
        return False
    return user

def create_access_token(data: dict, expires_delta: timedelta or None = None):
    """엑세스 토큰 생성 함수"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now() + expires_delta
    else:
        expire = datetime.now() + timedelta(minutes=15)

    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def create_refresh_token(data: dict, expires_delta: timedelta or None = None):
    """리프레시 토큰 생성 함수
    https://github.com/jason810496/FastAPI-Vue-OAuth2/blob/main/backend/setting/config.py#L19
    """
    to_encode = data.copy()
    # expire = datetime.utcnow() + timedelta(minutes=settings.access_token_expire_minutes)
    expire = datetime.now() + timedelta(minutes=REFRESH_TOKEN_EXPIRE_MINUTES)

    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode,# settings.refresh_token_secret,
                                 SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

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

def verify_token(token: str, db: Session) -> TokenData | None:
    """Verify a JWT token and return TokenData if valid.

    Parameters
    ----------
    token: str
        The JWT token to be verified.
    db: AsyncSession
        Database session for performing database operations.

    Returns
    -------
    TokenData | None
        TokenData instance if the token is valid, None otherwise.
    """
    is_blacklisted = crud_token_blacklist.exists(db, token=token)
    if is_blacklisted:
        return None

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username_or_email: str = payload.get("sub")
        if username_or_email is None:
            return None
        return TokenData(username_or_email=username_or_email)

    except JWTError:
        return None

async def blacklist_token(token: str, db: Session) -> None:
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    expires_at = datetime.fromtimestamp(payload.get("exp"))
    await crud_token_blacklist.create(db, object=TokenBlacklistCreate(**{"token": token, "expires_at": expires_at}))