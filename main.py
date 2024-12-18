# Necessary imports
from typing import Optional, List
from pydantic import BaseModel
from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from datetime import datetime, timedelta, timezone
from bson import ObjectId

# Database connection placeholder
from conn import db, SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES
from models import CategoryModel, BlogModel, BlogUpdateModel, TokenRequest, UserModel, WriterPermissionUpdateModel

# App setup
app = FastAPI()

# OAuth2 configuration
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")

# JWT Utilities
async def authenticate_user(username: str, password: str):
    user = db.users.find_one({"username": username})
    if user and user["password"] == password:
        return {"_id": str(user["_id"]), "username": user["username"], "role": user["role"]}
    return None

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc)  + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        role = payload.get("role")
        user_id = payload.get("user_id")
        if username is None or role is None:
            raise HTTPException(status_code=401, detail="Invalid token payload")
        return {"username": username, "role": role, "user_id": user_id}
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


# add user
@app.post("/admin/users", response_model=dict)
async def create_user(user: UserModel):
    """
    \nThis API is for creating a new users.\n
    \nparam user:\n
        - password:
        - role: It must be either "admin" or "writer".
        - username: It must be unique.
    \nreturn:\n
        Response message: Success.
    """
    # Check if the user with the same username, password, and role already exists
    existing_user = db.users.find_one({
        "username": user.username,
        "password": user.password,
        "role": user.role
    })
    if existing_user:
        raise HTTPException(
            status_code=400, detail="A user with the same username, password, and role already exists."
        )
    existing_user = db.users.find_one({
        "username": user.username,
        "role": user.role
    })
    if existing_user:
        raise HTTPException(
            status_code=400, detail="A user with the same username and role already exists."
        )
    existing_user = db.users.find_one({
        "username": user.username
    })
    if existing_user:
        raise HTTPException(
            status_code=400, detail="A user with the same username already exists, please enter unique username."
        )

    # Insert the new user
    user_data = user.model_dump()
    user_data["role"] = user.role.lower()
    if user.role == "admin" or user.role == "writer":
        result = db.users.insert_one(user_data)
        return {"id": str(result.inserted_id), "message": f"User created: {user.username}"}

    else:
        raise HTTPException(
            status_code=400, detail="A user with the same username, password, and role already exists."
        )


@app.post("/token", response_model=dict)
async def login_for_access_token(request: TokenRequest):
    """
        \nThis API is for creating a token for admin and writer.\n
        \nparam user:\n
            - role: It must be either "admin" or "writer".
            - username: It must be unique or which you already have an account.
        \nreturn:\n
            Response message: You will get access token and token type.
        """
    user = await authenticate_user(request.username, request.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or password")
    token_data = {"sub": user["username"], "role": user["role"], "user_id": user["_id"]}
    access_token = create_access_token(data=token_data)
    return {"access_token": access_token, "token_type": "bearer"}

# Category Utilities
async def validate_categories(category_ids: List[str]):
    for category_id in category_ids:
        category = db.categories.find_one({"_id": ObjectId(category_id), "is_active": True})
        if not category:
            raise HTTPException(status_code=400, detail=f"Invalid category ID: {category_id}")

# Admin-only routes
@app.post("/admin/categories", response_model=dict)
async def create_category(category: CategoryModel, user: dict = Depends(get_current_user)):
    """
    \nThis API is for updating categories\n
    \nparam user:\n
        - name: Category name need to pass.
        - description: Category description .
    \nreturn:\n
        Response message: Category created successfully with what name and ObjectId.
    """
    # Check if user is either admin or writer with permission
    if user["role"] == "admin":
        pass  # Admins are always allowed
    elif user["role"] == "writer":
        writer = db.users.find_one({"_id": ObjectId(user["user_id"])})
        if not writer or not writer.get("can_create_categories", False):
            raise HTTPException(status_code=403, detail="Sorry but you are not permitted to create categories")
    else:
        raise HTTPException(status_code=403, detail="Only admins or authorized writers can create categories")

    # Prepare category data for insertion
    category_data = category.model_dump()
    category_data["created_by"] = user["username"]
    category_data["user_id"] = ObjectId(user["user_id"])

    # Insert category into the database
    result = db.categories.insert_one(category_data)
    return {"id": str(result.inserted_id), "message": f"Category created: {category.name}"}



@app.get("/admin/categories", response_model=List[dict])
async def list_all_categories(user: dict = Depends(get_current_user)):
    """
    \nThis API is for getting list of dict of all active categories\n
    Response message: Get all active categories.
    """
    # Check if user is admin or writer with permission
    if user["role"] == "admin":
        filter_query = {"created_by": user["username"]}
    elif user["role"] == "writer":
        writer = db.users.find_one({"_id": ObjectId(user["user_id"])})
        if not writer or not writer.get("can_create_categories", False):
            raise HTTPException(status_code=403, detail="Writers are not permitted to view all categories")
        filter_query = {"created_by": user["username"]}
    else:
        raise HTTPException(status_code=403, detail="Only admins or authorized writers can view categories")

    # Fetch categories from database
    categories = db.categories.find(
        filter_query,
        {"name": 1, "description": 1, "is_active": 1, "created_by": 1, "user_id": 1}
    ).to_list(None)

    return [
        {
            "id": str(category["_id"]),
            "name": category.get("name", "N/A"),
            "description": category.get("description", "No description"),
            "is_active": category.get("is_active", False),
            "created_by": category.get("created_by", "Unknown"),
            "user_id": str(category.get("user_id", ""))
        }
        for category in categories
    ]

@app.put("/admin/categories/{category_id}", response_model=dict)
async def update_category(category_id: str, category: CategoryModel, user: dict = Depends(get_current_user)):
    """
        \nThis API is for updating categories\n
        \nparam user:\n
            - name: Category name need to pass.
            - description: Category description .
            - is_active: It must be set to true by default, but you change to false.
        \nreturn:\n
            Response message: Category updated successfully with what name.
        """
    # Check if user is admin or writer with permission
    if user["role"] == "admin":
        pass  # Admins are always allowed
    elif user["role"] == "writer":
        writer = db.users.find_one({"_id": ObjectId(user["user_id"])})
        if not writer or not writer.get("can_create_categories", False):
            raise HTTPException(status_code=403, detail="Writers are not permitted to update categories")
    else:
        raise HTTPException(status_code=403, detail="Only admins or authorized writers can update categories")

    # Ensure the user is only updating categories they created
    filter_query = {"_id": ObjectId(category_id), "created_by": user["username"]}
    update_data = {"$set": category.model_dump()}

    result = db.categories.update_one(filter_query, update_data)
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Category not found or you don't have permission to update it")

    return {"message": f"Category updated: {category.name}"}


@app.delete("/admin/categories/{category_id}", response_model=dict)
async def delete_category(category_id: str, user: dict = Depends(get_current_user)):
    """
        \nThis API is for deleting or deactivating categories\n
        \nparam user:\n
        - name: pass category ObjectId in url to delete.
        \nreturn:\n
            Response message: Category deleted or deactivated successfully.
        """
    # Check if user is admin or writer with permission
    if user["role"] == "admin":
        pass  # Admins are always allowed
    elif user["role"] == "writer":
        writer = db.users.find_one({"_id": ObjectId(user["user_id"])})
        if not writer or not writer.get("can_create_categories", False):
            raise HTTPException(status_code=403, detail="Writers are not permitted to delete categories")
    else:
        raise HTTPException(status_code=403, detail="Only admins or authorized writers can delete categories")

    # Deactivate the category
    result = db.categories.update_one({"_id": ObjectId(category_id), "created_by": user["username"]}, {"$set": {"is_active": False}})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Category not found or you don't have permission to delete it")

    return {"message": "Category deactivated successfully"}

async def validate_object_id(id: str, collection: str, active_only: bool = False):
    if not ObjectId.is_valid(id):
        raise HTTPException(status_code=400, detail=f"Invalid ObjectId: {id}")
    query = {"_id": ObjectId(id)}
    if active_only:
        query["is_active"] = True
    doc = db["categories"].find(query)
    if not doc:
        raise HTTPException(status_code=404, detail=f"Resource not found in {collection} for ID: {id}")
    return doc

# Blog Routes
@app.post("/writer/blogs", response_model=dict)
async def create_blog(blog: BlogModel, current_user: dict = Depends(get_current_user)):
    """
       \nThis API is for adding or creating blogs\n
       \nparam user:\n
           - title: Write blog title.
           - content: Write blog content .
           - categories: pass ObjectId of categories in list which blog title is representing.
       \nreturn:\n
           Response message: blogs created successfully with what title and ObjectId.
       """
    if current_user["role"] == "admin":
        pass
    elif current_user["role"] != "writer":
        raise HTTPException(status_code=403, detail="Only writers and admin can create blogs")
    validated_categories = []
    for category_id in blog.categories:
        await validate_object_id(category_id, "categories", active_only=True)
        validated_categories.append(ObjectId(category_id))
    blog_data = blog.model_dump()
    blog_data["author"] = current_user["username"]
    blog_data["user_id"] = ObjectId(current_user["user_id"])
    blog_data["categories"] = validated_categories
    result = db.blogs.insert_one(blog_data)
    return {"id": str(result.inserted_id), "message": f"Blog created: {blog.title}"}

@app.get("/writer/blogs", response_model=List[dict])
async def list_blogs(user: dict = Depends(get_current_user)):
    """
    This API is for getting a list of all blogs created.
    Response message: Get all blogs.
    """
    if user["role"] == "admin":
        pass
    elif user["role"] != "writer":
        raise HTTPException(status_code=403, detail="Only writers and admins can create blogs")

    blogs = db.blogs.find({"user_id": ObjectId(user["user_id"])}).to_list(None)

    # Convert ObjectId values to strings
    return [
        {
            "id": str(blog["_id"]),
            "title": blog.get("title", "No Title"),
            "content": blog.get("content", "No Content"),
            "categories": [str(category) for category in blog.get("categories", [])],
            # Directly convert ObjectId to string
            "author": blog.get("author", "Unknown"),
            "user_id": str(blog["user_id"])  # Directly convert ObjectId to string
        }
        for blog in blogs
    ]

@app.put("/writer/blogs/{blog_id}", response_model=dict)
async def update_blog(blog_id: str, blog: BlogUpdateModel, user: dict = Depends(get_current_user)):
    """
    \nThis API is for updating blogs\n
    \nparam user:\n
        - title: Write blog title .
        - content: Give description or content of api.
        - categories: Give ObjectId of categories in list which blog title is representing.
    \nreturn:\n
        Response message: blogs updated successfully with what ObjectId.
    """
    if user["role"] == "admin":
        pass
    elif user["role"] != "writer":
        raise HTTPException(status_code=403, detail="writer and admin only can update blogs")
    existing_blog = db.blogs.find({"_id": ObjectId(blog_id), "author": user["username"]})
    if not existing_blog:
        raise HTTPException(status_code=404, detail="Blog not found or access denied")
    validated_categories = []
    for category_id in blog.categories:
        await validate_object_id(category_id, "categories", active_only=True)
        validated_categories.append(ObjectId(category_id))
    blog_data = blog.model_dump()
    blog_data["categories"] = validated_categories
    blog_data["user_id"] = ObjectId(user["user_id"])
    db.blogs.update_one({"_id": ObjectId(blog_id)}, {"$set": blog_data})
    return {"message": f"Blog updated: {blog_id}"}

@app.delete("/writer/blogs/{blog_id}", response_model=dict)
async def delete_blog(blog_id: str, user: dict = Depends(get_current_user)):
    """
    \nThis API is for updating blogs\n
    \nparam user:\n
        give blog id(which is ObjectId) with token in authorization Bearer in Headers.
    \nreturn:\n
        Response message: blogs deleted successfully with what ObjectId.
    """
    if user["role"] == "admin":
        pass
    elif user["role"] != "writer":
        raise HTTPException(status_code=403, detail="Only writers and admin can create blogs")
    existing_blog = db.blogs.find_one({"_id": ObjectId(blog_id)})
    if not existing_blog:
        raise HTTPException(status_code=404, detail="Blog not found")
    if existing_blog["author"] != user["username"]:
        raise HTTPException(status_code=403, detail="Access denied")
    result = db.blogs.delete_one({"_id": ObjectId(blog_id), "author": user["username"]})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Failed to delete the blog")
    return {"message": f"Blog deleted: {blog_id}"}


@app.put("/admin/writers/{writer_username}/permissions", response_model=dict)
async def update_writer_permissions(
    writer_username: str,
    permissions: WriterPermissionUpdateModel,
    user: dict = Depends(get_current_user)
):
    """
    \nThis API is for updating blogs\n
    \nparam user:\n
        pass writer username in api for giving access.
    \nreturn:\n
        Response message: Successfully give access permissions with giving username.
    """
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Only admins can update writer permissions for creating categories")

    # Find the writer
    writer = db.users.find({"username": writer_username, "role": "writer"})
    if not writer:
        raise HTTPException(status_code=404, detail="Writer not found")

    # Update the writer's permission
    result = db.users.update_one(
        {"username": writer_username, "role": "writer"},
        {"$set": {"can_create_categories": permissions.can_create_categories}}
    )

    if result.matched_count == 0:
        raise HTTPException(status_code=400, detail="Failed to update permissions")

    return {"message": f"Updated 'can_create_categories' for {writer_username} to {permissions.can_create_categories}"}
