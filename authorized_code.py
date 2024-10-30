
import json
from typing import List
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2AuthorizationCodeBearer
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import requests

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# OAuth2 settings
AUTH0_DOMAIN = "dev-rseqmkudkz5c8lz0.us.auth0.com"
CLIENT_ID = "zXygKDhMnQbEsg3vPodPHJ8oeYIF8eo9"
CLIENT_SECRET = "pIHI8FgCYMNt7HOLaOcrufJQhIEUfA54NQhNEE739AoK7RZRQhEw9cjrfdKRIogq"
REDIRECT_URI = "http://localhost:5000/callback/"

oauth2_scheme = OAuth2AuthorizationCodeBearer(
    authorizationUrl=f"https://{AUTH0_DOMAIN}/authorize",
    tokenUrl=f"https://{AUTH0_DOMAIN}/oauth/token"
)

# Pydantic model for a Record
class Record(BaseModel):
    postId: int
    id: int
    name: str
    email: str
    body: str

# Load records from JSON file
def load_records_from_json(file_path: str) -> List[Record]:
    with open(file_path, "r") as file:
        records_data = json.load(file)
        return [Record(**record) for record in records_data]

try:
    records = load_records_from_json("data.json")
except FileNotFoundError:
    raise Exception("data.json file not found. Please ensure the file is in the correct directory.")


@app.get("/authorize/")
async def authorize():
    """
    Returns the authorization URL for the user to log in.
    """
    return {"authorization_url": f"https://{AUTH0_DOMAIN}/authorize?response_type=code&client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&scope=openid profile email"}

@app.get("/callback/")
async def callback(code: str):
    """
    Exchange authorization code for access token.
    """
    token = exchange_code_for_token(code)
    return {"access_token": token}

@app.get("/protected-data/")
async def protected_data(token: str = Depends(oauth2_scheme)):
    """
    Protected endpoint that requires a valid access token to access.
    """
    return [record.dict() for record in records]

def exchange_code_for_token(code: str):
    """
    Exchange authorization code for an access token.
    """
    token_url = f"https://{AUTH0_DOMAIN}/oauth/token"
    headers = {'Content-Type': 'application/json'}
    payload = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "code": code,
        "grant_type": "authorization_code",
        "redirect_uri": REDIRECT_URI
    }

    response = requests.post(token_url, headers=headers, json=payload)
    
    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail=response.json())
    
    return response.json().get("access_token")  # Extract access_token

def get_user_info(token: str):
    """
    Retrieve user information using the access token.
    """
    userinfo_url = f"https://{AUTH0_DOMAIN}/userinfo"
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(userinfo_url, headers=headers)

    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail="Failed to retrieve user info")
    
    return response.json()  # Return user information

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)


