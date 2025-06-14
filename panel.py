from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi_admin.app import app as admin_app
from fastapi_admin.providers import UsernamePasswordProvider
from fastapi_admin.resources import Model
from fastapi_admin.forms import inputs
from fastapi_admin import fields
from fastapi_admin.database import Database
from databases import Database
from sqlalchemy import create_engine, Column, Integer, String, Date, Float, MetaData, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional
import logging

# FastAPI app
app = FastAPI()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Database setup
DATABASE_URL = "sqlite:///./test.db"
database = Database(DATABASE_URL)
metadata = MetaData()
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base(metadata=metadata)

# Define the Client model
class Client(Base):
    __tablename__ = "clients"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    company = Column(String, index=True)
    date = Column(Date, index=True)
    revenue = Column(Float, index=True)

# Define the User model
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)

# Create tables
metadata.create_all(engine)

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT settings
SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# OAuth2
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Dependency to get the database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Password verification
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

# Hash password
def get_password_hash(password):
    return pwd_context.hash(password)

# Authenticate user
def authenticate_user(db, username: str, password: str):
    user = db.query(User).filter(User.username == username).first()
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    if not user.is_active:
        return False
    return user

# Create access token
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Get current user
async def get_current_user(token: str = Depends(oauth2_scheme), db=Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise credentials_exception
    return user

# Get current active user
async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if not current_user:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

# Get current active admin user
async def get_current_active_admin(current_user: User = Depends(get_current_active_user)):
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not enough permissions")
    return current_user

# FastAPI-Admin setup
admin_app.providers.append(
    UsernamePasswordProvider(
        admin_model=Client,
        login_logo_url="https://preview.tabler.io/static/logo-white.svg",
        admin_logo_url="https://preview.tabler.io/static/logo-white.svg",
        login_template="login.html",
        admin_template="admin.html",
    )
)

# Register the model with FastAPI-Admin
admin_app.register(
    Model(
        label="Clients",
        model=Client,
        fields=[
            fields.String(name="name"),
            fields.String(name="company"),
            fields.Date(name="date"),
            fields.Float(name="revenue"),
        ],
        form=inputs.Form(
            layout=[
                inputs.Layout(
                    [
                        inputs.Item(label="Name", name="name"),
                        inputs.Item(label="Company", name="company"),
                        inputs.Item(label="Date", name="date"),
                        inputs.Item(label="Revenue", name="revenue"),
                    ],
                ),
            ],
        ),
    )
)

# Include the admin app in the main app
app.mount("/admin", admin_app)

# Token endpoint
@app.post("/token")
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db=Depends(get_db)):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

# Protected endpoint to test authentication
@app.get("/users/me")
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    return current_user

# Function to add a user
def add_user(db: SessionLocal, username: str, password: str, is_admin: bool = False):
    hashed_password = get_password_hash(password)
    user = User(username=username, hashed_password=hashed_password, is_admin=is_admin)
    db.add(user)
    db.commit()
    db.refresh(user)
    return user

# Add a hardcoded admin user on startup
@app.on_event("startup")
async def startup_event():
    db = SessionLocal()
    # Check if the user already exists
    user = db.query(User).filter(User.username == "admin").first()
    if not user:
        # Hardcoded admin password
        admin_password = "admin"
        add_user(db, username="admin", password=admin_password, is_admin=True)
    db.close()

# Password reset request
@app.post("/request-password-reset")
async def request_password_reset(username: str, db=Depends(get_db)):
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    logger.info(f"Password reset requested for {username}")
    return {"message": "Password reset request received. Please use the reset link provided."}

# Password reset
@app.get("/reset-password")
async def reset_password(username: str, new_password: str, db=Depends(get_db)):
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.hashed_password = get_password_hash(new_password)
    db.commit()
    return {"message": "Password reset successfully"}

# User management endpoints
class UserUpdate(BaseModel):
    username: Optional[str] = None
    password: Optional[str] = None
    is_active: Optional[bool] = None
    is_admin: Optional[bool] = None

@app.put("/users/{user_id}", response_model=User)
async def update_user(user_id: int, user_update: UserUpdate, db=Depends(get_db), current_user: User = Depends(get_current_active_admin)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user_update.username:
        user.username = user_update.username
    if user_update.password:
        user.hashed_password = get_password_hash(user_update.password)
    if user_update.is_active is not None:
        user.is_active = user_update.is_active
    if user_update.is_admin is not None:
        user.is_admin = user_update.is_admin
    db.commit()
    db.refresh(user)
    return user

@app.delete("/users/{user_id}", response_model=User)
async def delete_user(user_id: int, db=Depends(get_db), current_user: User = Depends(get_current_active_admin)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    db.delete(user)
    db.commit()
    return user

# Run the application
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
