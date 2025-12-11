import os
from dotenv import load_dotenv
load_dotenv()

GOOGLE_CLIENT_ID = os.environ["GOOGLE_CLIENT_ID"]
GOOGLE_CLIENT_SECRET = os.environ["GOOGLE_CLIENT_SECRET"]
JWT_SECRET = os.environ["JWT_SECRET"]
SESSION_SECRET_KEY = os.environ["SESSION_SECRET"]
