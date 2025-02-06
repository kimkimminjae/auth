from click import DateTime

from database import get_db
from models import User
from passlib.context import CryptContext
from models import Role
from datetime import datetime

# SQL의 TIMESTAMP 타입은 Python의 datetime.datetime 객체와 호환됩니다.

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class Hasher:

    @staticmethod
    def get_password_hash(password):
        return pwd_context.hash(password)

    @staticmethod
    def verify_password(plain_password, hashed_password):
        return pwd_context.verify(plain_password, hashed_password)


def seed_admin():

    db = get_db()
    is_admin_exist = db.query(User).filter(User.email == "admin@gaion.kr").fist()
    if not is_admin_exist:
        admin = User(
            # id= uuid.uuid4(),model에서 설정해놓은 기본값 있기 때문에 여기서 설정할 필요가 없다.

            name="admin",
            email="admin@gaion.kr",

            emailVerified=datetime.now(),
            image="https://example.com",

            password=Hasher.get_password_hash("admin"),

            role=Role.ADMIN,
            # createdAt= datetime.now(),이 값은 sql에서 설정해놓은 기본값 있으므로 여기서 설정할 필요가 없다.
            #updatedAt=datetime.now(),  이 값은 model에서 설정해놓은 기본값 있으므로 여기서 설정할 필요가 없다.
        )

        db.add(admin)
        db.commit()
        db.refresh(admin)
        print("Admin user created")
    else:
        print("Admin user already exists")
