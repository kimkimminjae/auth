from setting.database import get_db
from auth.model.auth_model import User
from auth.model.auth_model import Role
from datetime import datetime
from auth.utils.authenticate import Hasher
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
