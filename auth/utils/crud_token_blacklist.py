from fastcrud import FastCRUD

from auth.model.auth_model import TokenBlacklist
from auth.model.auth_shemas import TokenBlacklistCreate, TokenBlacklistUpdate

CRUDTokenBlacklist = FastCRUD[TokenBlacklist, TokenBlacklistCreate, TokenBlacklistUpdate, None, None, None]
crud_token_blacklist = CRUDTokenBlacklist(TokenBlacklist)