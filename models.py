# Pydantic models
from typing import Optional, List

from bson import ObjectId
from pydantic import BaseModel

class UserModel(BaseModel):
    username: str
    password: str
    role: str
    can_create_categories: Optional[bool] = False

    class Config:
        json_schema_extra = {
            "example": {
                "username": "writer123",
                "password": "writer@123",
                "role": "admin",  # Options: "admin" or "writer"
                "can_create_categories: Optional[bool]": False
            }
        }

class WriterPermissionUpdateModel(BaseModel):
    can_create_categories: bool


class TokenData(BaseModel):
    username: str
    password: str
    role: str

    class Config:
        json_schema_extra = {
            "example": {
                "username": "admin",
                "password": "admin@1.",
                "role": "admin"
            }
        }

class TokenRequest(BaseModel):
    username: str
    password: str

    class Config:
        json_schema_extra = {"example": {"username": "admin", "password": "admin@1."}}



class CategoryModel(BaseModel):
    name: str
    description: Optional[str] = None
    is_active: bool = True

    class Config:
        json_schema_extra = {
            "example": {
                "name": "Technology",
                "description": "Posts related to technology",
                "is_active": True
            }
        }

class BlogModel(BaseModel):
    title: str
    content: str
    categories: List[str]
    author: Optional[str] = None

    class Config:
        json_schema_extra = {
            "example": {
                "title": "The Future of AI",
                "content": "Exploring the advancements and challenges in AI.",
                "categories": ["A"],
                "author": "writer123",
                "user_id": "60d21b4667d0d8992e610c85"
            }
        }

class BlogUpdateModel(BaseModel):
    title: Optional[str]
    content: Optional[str]
    categories: Optional[List[str]]

    class Config:
        json_schema_extra = {
            "example": {
                "title": "The Future of AI - Updated",
                "content": "An updated exploration of AI advancements.",
                "categories": ["60d21b4667d0d8992e610c85", "60d21b4667d0d8992e610c86"]
            }
        }
