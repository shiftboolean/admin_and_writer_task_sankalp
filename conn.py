from pymongo import MongoClient
from dotenv import load_dotenv
import os

# Load environment variables from .env file
load_dotenv()

# Read values from .env
MONGO_URI = os.getenv("MONGO_URI")
DB_NAME = os.getenv("DB_NAME")
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30))

# Connect to MongoDB
client = MongoClient(MONGO_URI)
db = client[DB_NAME]


# from pymongo import MongoClient
#
# client = MongoClient("mongodb+srv://sankalpmishra:HngMpG0UuvaHU196@blogmanagement.e70pb.mongodb.net/")
# db = client.blog_management
#
# SECRET_KEY = "l3Wc5PGGoVd4okdfdtH0sewAyiwUYabygWEcZAQvYks"
# ALGORITHM = "HS256"
# ACCESS_TOKEN_EXPIRE_MINUTES = 30
