from fastapi import FastAPI, Depends, HTTPException, status, BackgroundTasks
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from typing import List
from fastapi_limiter import FastAPILimiter
from fastapi_limiter.depends import RateLimiter
from fastapi.middleware.cors import CORSMiddleware
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig
import redis

from . import models, schemas, crud, auth
from .database import SessionLocal, engine
from .config import settings


models.Base.metadata.create_all(bind=engine)
app = FastAPI()

limiter = FastAPILimiter(
    key_func=lambda _: "global",  
    rate_limits={
        "contacts": "100/minute",  
        "register": "5/minute",    
    }
)

# Увімкнення CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@app.on_event("startup")
async def startup_event():
    redis_client = redis.StrictRedis(host="localhost", port=6379, db=0)
    await limiter.init(redis_client)


@app.on_event("shutdown")
async def shutdown_event():
    await limiter.shutdown()


@app.post("/register/", response_model=schemas.User, dependencies=[Depends(RateLimiter(limit="5/minute"))])
async def register_user(user: schemas.UserCreate, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    return await auth.register_user(user, db, background_tasks)


@app.get("/verify/")
async def verify_email(token: str, db: Session = Depends(get_db)):
    return await auth.verify_email(token, db)


@app.post("/token/", response_model=schemas.Token)
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    return auth.login_for_access_token(form_data, db)

# обмеження швидкості створення контактів (100 запитів на хвилину)
@app.post("/contacts/", response_model=schemas.Contact, dependencies=[Depends(RateLimiter(limit="100/minute"))])
def create_contact(contact: schemas.ContactCreate, current_user: schemas.User = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    return crud.create_contact(db, contact)


@app.put("/users/avatar/", response_model=schemas.User)
def update_avatar(avatar_url: str, current_user: schemas.User = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    return auth.update_avatar(current_user, avatar_url, db)

