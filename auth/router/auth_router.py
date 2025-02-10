from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Response
from fastapi.security import OAuth2PasswordRequestForm
from fastcrud.exceptions.http_exceptions import UnauthorizedException
from jose import JWTError
from starlette import status
from starlette.requests import Request

from auth.utils.authenticate import Hasher, authenticate_user, create_access_token, create_refresh_token, \
    get_current_user, blacklist_token, ACCESS_TOKEN_EXPIRE_MINUTES, REFRESH_TOKEN_EXPIRE_MINUTES, verify_token
from setting.database import get_db
from sqlalchemy.orm import Session

from auth.model.auth_shemas import RegisterRequestDto, Token
from auth.model.auth_model import User, Role
import logging
from fastapi.responses import JSONResponse

from auth.utils.authenticate import oauth_scheme

auth_router = APIRouter(prefix="/auth")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@auth_router.post("/register/")
def register(user: RegisterRequestDto, db: Session = Depends(get_db)) -> JSONResponse:
    """회원가입"""
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
    # https://inpa.tistory.com/entry/WEB-%F0%9F%93%9A-Access-Token-Refresh-Token-%EC%9B%90%EB%A6%AC-feat-JWT



@auth_router.post("/token", response_model=Token)
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

    refresh_token = await create_refresh_token(data={"username":  user.email})

    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        samesite="strict", #Lax, Strict, None
        secure=True,
        # expires=timedelta(settings.refresh_token_expire_minutes),
        expires= datetime.now() + timedelta(minutes=REFRESH_TOKEN_EXPIRE_MINUTES)
    )

    return Token(
        access_token=access_token,
        token_type="Bearer"
    )
# https://www.reddit.com/r/FastAPI/comments/1fed43y/oauth2_example_logout_and_refresh_token/?rdt=53446


@auth_router.post("/logout")
async def logout(response: Response) -> JSONResponse:
    response.delete_cookie("refresh_token") #서버에서는 쿠키 내 refresh_token을 삭제하고
    # return {"message": "Logout successfully"} # fastapi는 dict일 때 자동 직렬화됨 type은 dict
    return JSONResponse(content={"message": "Logout successfully"}) #이후 프론트에서 access_token을 삭제하도록 하면 됨

@auth_router.post("/logout2")
async def logout(response: Response, access_token: str = Depends(oauth_scheme), db: Session = Depends(get_db)) -> dict[str, str]:

        try:
            await blacklist_token(token=access_token, db=db) #access_token을 블랙리스트에 추가하는 로직 추가함
            response.delete_cookie(key="refresh_token")

            return {"message": "Logged out successfully"}

        except JWTError:
            raise UnauthorizedException("Invalid token.")

@auth_router.post("/refresh")
async def refresh_access_token(request: Request, db:Session = Depends(get_db)) -> dict[str, str]:
    refresh_token = request.cookies.get("refresh_token")
    if not refresh_token:
        raise UnauthorizedException("Refresh token missing.")

    user_data = verify_token(refresh_token, db)
    if not user_data:
        raise UnauthorizedException("Invalid refresh token.")

    new_access_token = await create_access_token(data={"sub": user_data.username_or_email})
    return {"access_token": new_access_token, "token_type": "bearer"}



@auth_router.get("/users/me")
async def read_users_me(current_user: User = Depends(get_current_user)):
    """https://databoom.tistory.com/entry/FastAPI-JWT-%EA%B8%B0%EB%B0%98-%EC%9D%B8%EC%A6%9D-6"""
    return {"current_user": current_user}




