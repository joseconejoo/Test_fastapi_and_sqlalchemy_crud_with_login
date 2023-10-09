from pydantic import BaseModel
from typing import List, Optional


class TokenData(BaseModel):
    username: Optional[str] = None

class ItemBase(BaseModel):
    title: str
    description: str
    user_id: int

class ItemCreate(ItemBase):
    pass

class Item(ItemBase):
    id: int
    completed: bool

    class Config:
        from_attributes = True

class ItemList(BaseModel):
    items: List[Item]

class ItemResponse(BaseModel):
    item: Item
    message: str

class UserBase(BaseModel):
    username: str

class UserCreate(UserBase):
    password: str

class User(UserBase):
    id: int
    items: List[Item] = []

    class Config:
        from_attributes = True