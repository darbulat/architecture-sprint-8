import os

from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt
from jose.exceptions import JWTError
import requests

app = FastAPI()
security = HTTPBearer()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

ALGORITHM = "RS256"
KEYCLOAK_URL = os.environ.get("KEYCLOAK_URL", "http://localhost:8080")
REALM_NAME = os.environ.get("REALM_NAME", "reports-realm")
CLIENT_ID = os.environ.get("CLIENT_ID", "reports-api")

jwks = {}


def get_jwks():
    global jwks
    if not jwks:
        url = f"{KEYCLOAK_URL}/realms/{REALM_NAME}/protocol/openid-connect/certs"
        response = requests.get(url)
        response.raise_for_status()
        jwks = response.json()
    return jwks


def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    token = credentials.credentials
    jwks = get_jwks()

    key = get_signing_key(token, jwks)
    payload = decode_token(token, key)
    verify_roles(payload)

    return payload


def get_signing_key(token: str, jwks: dict) -> dict:
    """Retrieve the signing key from JWKS based on the token's kid."""
    unverified_header = jwt.get_unverified_header(token)
    kid = unverified_header["kid"]
    key = next((key for key in jwks["keys"] if key["kid"] == kid), None)

    if key is None:
        raise HTTPException(status_code=401, detail="Invalid token.")

    return key


def decode_token(token: str, key: dict) -> dict:
    """Decode the JWT token and verify its claims."""
    payload = jwt.decode(
        token,
        key,
        algorithms=[ALGORITHM],
        audience=CLIENT_ID,
        issuer=f"http://localhost:8080/realms/{REALM_NAME}"
    )

    return payload


def verify_roles(payload: dict) -> None:
    """Check if the user has the required roles."""
    roles = payload.get("realm_access", {}).get("roles", [])
    if not roles:
        raise HTTPException(status_code=401, detail="Forbidden: No roles found.")

    if "prothetic_user" not in roles:
        raise HTTPException(status_code=401, detail="Forbidden: You do not have access to this resource.")


@app.get("/reports")
async def get_reports(token: dict = Depends(verify_token)) -> FileResponse:
    report_file_path = os.path.abspath("./report.pdf")
    if not os.path.exists(report_file_path):
        raise HTTPException(status_code=404, detail="Report file not found")
    return FileResponse(report_file_path, media_type="application/pdf", filename="report.pdf")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
