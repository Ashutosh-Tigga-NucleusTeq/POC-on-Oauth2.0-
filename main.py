import json
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2AuthorizationCodeBearer
from jose import JWTError, jwt
from pydantic import BaseModel
from typing import List
from fastapi.middleware.cors import CORSMiddleware
import requests

app = FastAPI()

# CORS settings
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins; adjust this for security
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods; adjust as needed
    allow_headers=["*"],  # Allows all headers; adjust as needed
)

# OAuth2 settings for Auth0 (replace these with your own Auth0 settings)
AUTH0_DOMAIN = "dev-rseqmkudkz5c8lz0.us.auth0.com"
API_AUDIENCE = "urn:dev-rseqmkudkz5c8lz0:myapi"
ALGORITHMS = ["RS256"]

# URL to fetch JWKS (JSON Web Key Set) from Auth0
JWKS_URL = f"https://{AUTH0_DOMAIN}/.well-known/jwks.json"
jwks_data = requests.get(JWKS_URL).json()

# OAuth2AuthorizationCodeBearer instance
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

# Utility function to validate JWT using the JWKS data
def get_rsa_key(kid: str):
    """
    Find the RSA key from JWKS that matches the `kid` (Key ID).
    """
    for key in jwks_data["keys"]:
        if key["kid"] == kid:
            return {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Public key not found.")

def verify_token(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        # Decode token without verification to extract the `kid` (Key ID)
        unverified_header = jwt.get_unverified_header(token)
        rsa_key = get_rsa_key(unverified_header["kid"])
        
        # Decode and verify the JWT using the RSA key
        payload = jwt.decode(
            token,
            rsa_key,
            algorithms=ALGORITHMS,
            audience=API_AUDIENCE,
            issuer=f"https://{AUTH0_DOMAIN}/"
        )
        return payload  # Return the token's payload if successful
    except JWTError:
        raise credentials_exception

@app.get("/records/", response_model=List[Record])
def get_records(token_data: dict = Depends(verify_token)):
    """
    Endpoint to get records. Requires OAuth2 authentication.
    """
    return [record.dict() for record in records]

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5001)


