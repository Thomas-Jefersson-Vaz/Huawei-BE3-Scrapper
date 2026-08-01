"""
SCRAM authentication cryptography for Huawei HarmonyOS routers.

Implements the challenge-response protocol used by Huawei WiFi BE3 (WS8100)
and similar HarmonyOS-based routers. Uses PBKDF2-SHA256 for key derivation
and HMAC-SHA256 for proof generation.

Based on reverse-engineering from:
https://github.com/vmakeev/huawei_mesh_router
"""

import hashlib
import hmac
from random import randbytes


def generate_nonce() -> str:
    """Generate a 32-byte random client nonce as a hex string."""
    return randbytes(32).hex()


def get_client_proof(
    password: str,
    salt: str,
    iterations: int,
    first_nonce: str,
    server_nonce: str,
) -> str:
    """
    Generate the SCRAM client proof for authentication.

    The proof is computed as:
        salted_password = PBKDF2(password, salt, iterations)
        client_key = HMAC(salted_password, "Client Key")
        stored_key = SHA256(client_key)
        auth_msg = first_nonce + "," + server_nonce + "," + server_nonce
        client_signature = HMAC(stored_key, auth_msg)
        client_proof = client_key XOR client_signature

    Args:
        password: The admin password in plaintext.
        salt: Hex-encoded salt from the server.
        iterations: PBKDF2 iteration count from the server.
        first_nonce: The client nonce sent in the first request.
        server_nonce: The server nonce received in the response.

    Returns:
        Hex-encoded client proof string.
    """
    salted_password = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        bytearray.fromhex(salt),
        iterations,
        32,
    )

    auth_msg = first_nonce + "," + server_nonce + "," + server_nonce

    client_key = hmac.new(
        salted_password, "Client Key".encode("utf-8"), hashlib.sha256
    ).digest()

    stored_key = hashlib.sha256(client_key).digest()

    client_signature = hmac.new(
        stored_key, auth_msg.encode("utf-8"), hashlib.sha256
    ).digest()

    client_proof = bytes(
        key ^ sign for (key, sign) in zip(client_key, client_signature)
    )

    return client_proof.hex()
