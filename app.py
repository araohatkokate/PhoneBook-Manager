from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, field_validator
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime, timedelta
import logging
from typing import Optional
from jose import jwt, JWTError
from passlib.context import CryptContext
from contextlib import asynccontextmanager
import re

# JWT Configuration
SECRET_KEY = "your_secret_key_here"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 120

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT Dependency
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Create the FastAPI app
app = FastAPI()

# Configure logging for authentication failures
logging.basicConfig(filename="auth_log.log", level=logging.INFO)

# Create the SQLite database engine
engine = create_engine("sqlite:///phonebook.db", echo=True)

# Create the base class for the database models
Base = declarative_base()

# Create the PhoneBook model class
class PhoneBook(Base):
    __tablename__ = "phonebook"
    id = Column(Integer, primary_key=True)
    full_name = Column(String)
    phone_number = Column(String)

# Create the database schema
Base.metadata.create_all(engine)

# Create the session class for database operations
Session = sessionmaker(bind=engine)

# Regular expressions for input validation
NAME_REGEX = re.compile(
    r"^([A-Za-z]+(?:[-'][A-Za-z]+)*)(?:, ([A-Za-z]+(?:[-'][A-Za-z]*)*)(?: ([A-Za-z]+(?:[-'][A-Za-z]*)*))?)?$"
)
PHONE_REGEX = re.compile(
    r"^(?:\+|011)?[ ]?(\d{1,4})?[ ]?[-. (]*\d{1,5}\)?[-. ]*\d{1,5}[-. ]*\d{1,5}(?:[-. ]*\d{1,5})?$"
)

# Helper function for sanitizing phone numbers
def normalize_phone_number(phone_number: str) -> str:
    """
    Normalize the phone number by removing all non-numeric characters except '+'.
    """
    sanitized_number = re.sub(r"[^\d+]", "", phone_number)  # Keep only digits and '+'
    return sanitized_number

# Function to normalize existing phone numbers in the database
def normalize_existing_phone_numbers():
    session = Session()
    try:
        phonebook_entries = session.query(PhoneBook).all()
        for entry in phonebook_entries:
            normalized_number = normalize_phone_number(entry.phone_number)
            if entry.phone_number != normalized_number:
                logging.info(f"Normalizing: {entry.phone_number} -> {normalized_number}")
                entry.phone_number = normalized_number
        session.commit()
    except Exception as e:
        logging.error(f"Error normalizing phone numbers: {e}")
        session.rollback()
    finally:
        session.close()

# Run normalization at startup
from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Perform startup tasks here
    normalize_existing_phone_numbers()
    yield  # Yield control to run the application
    # Perform shutdown tasks here (if needed)

app = FastAPI(lifespan=lifespan)


# User credentials for demonstration (hashed passwords)
USERS_DB = {
    "read_user": {"username": "read_user", "hashed_password": pwd_context.hash("read_password"), "role": "read"},
    "readwrite_user": {"username": "readwrite_user", "hashed_password": pwd_context.hash("write_password"), "role": "readwrite"},
}

# Pydantic model for validation
class Person(BaseModel):
    full_name: str
    phone_number: str

    @field_validator("full_name")
    def validate_full_name(cls, value):
        if not NAME_REGEX.match(value):
            logging.error(f"Invalid full_name input: {value}")
            log_action("INVALID_INPUT", name=value, message="Invalid name format")
            raise ValueError("Invalid name format")
        return value

    @field_validator("phone_number")
    def validate_phone_number(cls, value):
        if not PHONE_REGEX.match(value):
            logging.error(f"Invalid phone_number input: {value}")
            log_action("INVALID_INPUT", phone_number=value, message="Invalid phone number format")
            raise ValueError("Invalid phone number format")
        return normalize_phone_number(value)



# Helper Functions for Password Verification and Token Creation
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# JWT Authentication Functions
def authenticate_user(username: str, password: str):
    user = USERS_DB.get(username)
    if not user or not verify_password(password, user["hashed_password"]):
        return None
    return user

def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        role: str = payload.get("role")
        if username is None or role is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return {"username": username, "role": role}
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

def require_readwrite(current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "readwrite":
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    return current_user

# Token Endpoint
@app.post("/token")
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or password")
    access_token = create_access_token(
        data={"sub": user["username"], "role": user["role"]}
    )
    return {"access_token": access_token, "token_type": "bearer"}

# Audit logging function
def log_action(action: str, name: str = None, phone_number: str = None, message: str = None):
    with open("audit.log", "a") as f:
        log_entry = f"{datetime.now()} - ACTION: {action}"
        if name:
            log_entry += f", NAME: {name}"
        if phone_number:
            log_entry += f", PHONE: {phone_number}"
        if message:
            log_entry += f", MESSAGE: {message}"
        log_entry += "\n"
        f.write(log_entry)

# Exception handler for RequestValidationError
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    for error in exc.errors():
        if "full_name" in error["loc"]:
            logging.error(f"Invalid full_name: {error['input']}")
            log_action("INVALID_INPUT", name=error["input"], message="Invalid name format")
        elif "phone_number" in error["loc"]:
            logging.error(f"Invalid phone_number: {error['input']}")
            log_action("INVALID_INPUT", phone_number=error["input"], message="Invalid phone number format")
    return JSONResponse(status_code=400, content={"detail": "Invalid input data"})

# API Endpoints
@app.get("/PhoneBook/list")
def list_phonebook(current_user: dict = Depends(get_current_user)):
    session = Session()
    phonebook = session.query(PhoneBook).all()
    session.close()
    log_action("LIST")
    return phonebook

@app.post("/PhoneBook/add")
def add_person(person: Person, current_user: dict = Depends(require_readwrite)):
    session = Session()
    normalized_phone_number = normalize_phone_number(person.phone_number)
    existing_person = session.query(PhoneBook).filter_by(phone_number=normalized_phone_number).first()
    if existing_person:
        session.close()
        raise HTTPException(status_code=400, detail="Person already exists in the database")
    new_person = PhoneBook(full_name=person.full_name, phone_number=normalized_phone_number)
    session.add(new_person)
    session.commit()
    log_action("ADD", name=person.full_name, phone_number=normalized_phone_number)
    session.close()
    return {"message": "Person added successfully"}

@app.put("/PhoneBook/deleteByNumber")
def delete_by_number(phone_number: str, current_user: dict = Depends(require_readwrite)):
    session = Session()
    sanitized_phone_number = normalize_phone_number(phone_number)
    logging.debug(f"Sanitized phone number for query: {sanitized_phone_number}")
    print(f"Sanitized phone number for query: {sanitized_phone_number}")
    
    person = session.query(PhoneBook).filter_by(phone_number=sanitized_phone_number).first()
    if not person:
        logging.debug(f"Person not found with phone number: {sanitized_phone_number}")
        print(f"Person not found with phone number: {sanitized_phone_number}")
        session.close()
        raise HTTPException(status_code=404, detail="Person not found in the database")
    session.delete(person)
    session.commit()
    logging.debug(f"Person deleted: {sanitized_phone_number}")
    log_action("DELETE_BY_NUMBER", phone_number=sanitized_phone_number)
    session.close()
    return {"message": "Person deleted successfully"}

@app.put("/PhoneBook/deleteByName")
def delete_by_name(full_name: str, current_user: dict = Depends(require_readwrite)):
    session = Session()
    person = session.query(PhoneBook).filter_by(full_name=full_name).first()
    if not person:
        session.close()
        raise HTTPException(status_code=404, detail="Person not found in the database")
    session.delete(person)
    session.commit()
    log_action("DELETE_BY_NAME", name=full_name)
    session.close()
    return {"message": "Person deleted successfully"}
