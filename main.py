from fastapi import FastAPI, HTTPException
# import bcrypt
import uvicorn
from dto import RegisterRequestDto
app = FastAPI()


# def hash_password(password):
#    password = "MySecretPassword"
#    password_bytes = password.encode('utf-8')
#    hashed_bytes = bcrypt.hashpw(password_bytes, bcrypt.gensalt())
#    return hashed_bytes.decode('utf-8')

# Usage example

# 가상 사용자 저장소
fake_users_db = {}

@app.post("/register/")
async def register(user: RegisterRequestDto) -> None:
    # hashed_password = hash_password("MySecretPassword")
    #
    # if user.username in fake_users_db:
    #     raise HTTPException(status_code=400, detail="Username already exists")
    print(user)

    # return {"유저": user.name,
    #         "이메일": user.email,
    #         "해시된 비밀번호": hashed_password}

@app.get("/")
async def root():
    return {"message": "Hello World"}


@app.get("/hello/{name}")
async def say_hello(name: str):
    return {"message": f"Hello {name}"}


if __name__ == '__main__':
    uvicorn.run(app, port=8080, host='localhost')