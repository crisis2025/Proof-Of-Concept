# Agent PQC complet chronométré : Dilithium2 (signature) + Kyber512 (KEM) + AES‑GCM
#
# Les temps d’exécution sont mesurés pour :
#   • génération des paires de clés (Dilithium & Kyber)
#   • signature
#   • vérification
#   • encapsulation Kyber + chiffrement AES‑GCM
#   • décapsulation Kyber + déchiffrement AES‑GCM
#
# Chaque route retourne désormais le/des champ(s) "time_*_ms"
# contenant le temps en millisecondes.

from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import ctypes
import base58
import base64
import json
import os
import time      # ⬅️  Nouveau
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"]
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

liboqs = ctypes.cdll.LoadLibrary("/usr/local/lib/liboqs.so")
c_void_p = ctypes.c_void_p

# --- Signature bindings ---
liboqs.OQS_SIG_new.restype = c_void_p
liboqs.OQS_SIG_free.argtypes = [c_void_p]
liboqs.OQS_SIG_keypair.argtypes = [c_void_p, ctypes.c_void_p, ctypes.c_void_p]
liboqs.OQS_SIG_sign.argtypes = [c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t),
                                ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p]
liboqs.OQS_SIG_verify.argtypes = [c_void_p, ctypes.c_void_p, ctypes.c_size_t,
                                  ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p]

# --- KEM bindings ---
liboqs.OQS_KEM_new.restype = c_void_p
liboqs.OQS_KEM_free.argtypes = [c_void_p]
liboqs.OQS_KEM_keypair.argtypes = [c_void_p, ctypes.c_void_p, ctypes.c_void_p]
liboqs.OQS_KEM_encaps.argtypes = [c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
liboqs.OQS_KEM_decaps.argtypes = [c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]

KEY_STORAGE_FILE = "pqc_keys.json"

class OQS_SIG(ctypes.Structure):
    _fields_ = [
        ("method_name", ctypes.c_char_p),
        ("alg_version", ctypes.c_char_p),
        ("claimed_nist_level", ctypes.c_uint),
        ("euf_cma", ctypes.c_bool),
        ("length_public_key", ctypes.c_size_t),
        ("length_secret_key", ctypes.c_size_t),
        ("length_signature", ctypes.c_size_t),
        ("keypair", ctypes.c_void_p),
        ("sign", ctypes.c_void_p),
        ("verify", ctypes.c_void_p),
        ("free", ctypes.c_void_p)
    ]

class OQS_KEM(ctypes.Structure):
    _fields_ = [
        ("method_name", ctypes.c_char_p),
        ("alg_version", ctypes.c_char_p),
        ("claimed_nist_level", ctypes.c_uint),
        ("ind_cca", ctypes.c_bool),
        ("length_public_key", ctypes.c_size_t),
        ("length_secret_key", ctypes.c_size_t),
        ("length_ciphertext", ctypes.c_size_t),
        ("length_shared_secret", ctypes.c_size_t),
        ("keypair", ctypes.c_void_p),
        ("encaps", ctypes.c_void_p),
        ("decaps", ctypes.c_void_p),
        ("free", ctypes.c_void_p)
    ]

# ---------- Schémas de requête ----------
class EncryptRequest(BaseModel):
    did: str
    plaintext: str

class DecryptRequest(BaseModel):
    did: str
    ciphertext_kem: str
    ciphertext_data: str
    nonce: str

class PQCKeyGenRequest(BaseModel):
    did: str

class PQCSignRequest(BaseModel):
    did: str
    message: str

class PQCVerifyRequest(BaseModel):
    did: str
    message: str
    signature: str

# ---------- Persistance des clés ----------
def load_keys():
    if os.path.exists(KEY_STORAGE_FILE):
        with open(KEY_STORAGE_FILE, "r") as file:
            return json.load(file)
    return {}

def save_keys(keys):
    with open(KEY_STORAGE_FILE, "w") as file:
        json.dump(keys, file, indent=4)

# ---------- Sécurité ----------
def get_current_token(token: str = Depends(oauth2_scheme)):
    if token != "securetoken":
        raise HTTPException(status_code=403, detail="Invalid token")

# ---------- Routes ----------
@app.post("/generate_key_pqc")
def generate_key_pqc(req: PQCKeyGenRequest, token: str = Depends(get_current_token)):
    keys = load_keys()
    if req.did in keys:
        return keys[req.did]

    # --- Génération Dilithium ---
    start_dil = time.perf_counter()
    pq_algorithm = b"Dilithium2"
    sig_ptr = liboqs.OQS_SIG_new(pq_algorithm)
    oqs_sig = OQS_SIG.from_address(sig_ptr)

    pk = (ctypes.c_ubyte * oqs_sig.length_public_key)()
    sk = (ctypes.c_ubyte * oqs_sig.length_secret_key)()

    result = liboqs.OQS_SIG_keypair(sig_ptr, pk, sk)
    liboqs.OQS_SIG_free(sig_ptr)
    dilithium_ms = (time.perf_counter() - start_dil) * 1000

    # --- Génération Kyber ---
    start_kem = time.perf_counter()
    kem_ptr = liboqs.OQS_KEM_new(b"Kyber512")
    oqs_kem = OQS_KEM.from_address(kem_ptr)

    pk_kem = (ctypes.c_ubyte * oqs_kem.length_public_key)()
    sk_kem = (ctypes.c_ubyte * oqs_kem.length_secret_key)()

    liboqs.OQS_KEM_keypair(kem_ptr, pk_kem, sk_kem)
    liboqs.OQS_KEM_free(kem_ptr)
    kyber_ms = (time.perf_counter() - start_kem) * 1000

    keys[req.did] = {
        "dilithium_public_key": base58.b58encode(bytearray(pk)).decode(),
        "dilithium_private_key": base58.b58encode(bytearray(sk)).decode(),
        "kyber_public_key": base64.b64encode(bytearray(pk_kem)).decode(),
        "kyber_private_key": base64.b64encode(bytearray(sk_kem)).decode(),
    }
    print("##########################GENERATKEYS GENERATIONS#################################")
    print(f"time_keygen_dilithium_ms {round(dilithium_ms, 3)}")
    print(f"time_keygen_kyber_ms {round(kyber_ms, 3)}")

    save_keys(keys)
    return keys[req.did]

@app.post("/sign_pqc")
def sign_pqc(req: PQCSignRequest, token: str = Depends(get_current_token)):
    keys = load_keys()
    if req.did not in keys:
        raise HTTPException(status_code=404, detail="DID not found")

    pq_algorithm = b"Dilithium2"
    sig_ptr = liboqs.OQS_SIG_new(pq_algorithm)
    oqs_sig = OQS_SIG.from_address(sig_ptr)
    sk = base58.b58decode(keys[req.did]["dilithium_private_key"])

    message_bytes = req.message.encode()
    sig = (ctypes.c_ubyte * oqs_sig.length_signature)()
    sig_len = ctypes.c_size_t()

    start_sign = time.perf_counter()
    result = liboqs.OQS_SIG_sign(
        sig_ptr, sig, ctypes.byref(sig_len),
        message_bytes, len(message_bytes),
        sk
    )
    sign_ms = (time.perf_counter() - start_sign) * 1000
    liboqs.OQS_SIG_free(sig_ptr)

    if result != 0:
        raise HTTPException(status_code=500, detail="Signature failed")
    print("##########################OPERATION DE SIGNATURE#################################")
    print(f"time_sign_ms: {round(sign_ms, 3)}")
    return {
        "signature": base58.b58encode(bytearray(sig[:sig_len.value])).decode(),
    }

@app.post("/verify_pqc")
def verify_pqc(req: PQCVerifyRequest, token: str = Depends(get_current_token)):
    keys = load_keys()
    if req.did not in keys:
        raise HTTPException(status_code=404, detail="DID not found")

    pq_algorithm = b"Dilithium2"
    sig_ptr = liboqs.OQS_SIG_new(pq_algorithm)
    oqs_sig = OQS_SIG.from_address(sig_ptr)

    pk = base58.b58decode(keys[req.did]["dilithium_public_key"])
    message_bytes = req.message.encode()
    signature_bytes = base58.b58decode(req.signature)

    start_verify = time.perf_counter()
    result = liboqs.OQS_SIG_verify(
        sig_ptr,
        message_bytes, len(message_bytes),
        signature_bytes, len(signature_bytes),
        pk
    )
    verify_ms = (time.perf_counter() - start_verify) * 1000
    liboqs.OQS_SIG_free(sig_ptr)

    print("##########################SIGNATURE VERIFICATION#################################")

    print(f"time_verify_ms: {round(verify_ms, 3)}")

    return {
        "valid": result == 0,
    }

@app.post("/encrypt_data")
def encrypt_data(req: EncryptRequest, token: str = Depends(get_current_token)):
    keys = load_keys()
    if req.did not in keys:
        raise HTTPException(status_code=404, detail="Public key not found")

    # --- Encapsulation Kyber ---
    kem_ptr = liboqs.OQS_KEM_new(b"Kyber512")
    oqs_kem = OQS_KEM.from_address(kem_ptr)
    pubkey = base64.b64decode(keys[req.did]["kyber_public_key"])

    ct = (ctypes.c_ubyte * oqs_kem.length_ciphertext)()
    ss = (ctypes.c_ubyte * oqs_kem.length_shared_secret)()

    start_kem = time.perf_counter()
    liboqs.OQS_KEM_encaps(kem_ptr, ct, ss, pubkey)
    kem_ms = (time.perf_counter() - start_kem) * 1000
    liboqs.OQS_KEM_free(kem_ptr)

    # --- Chiffrement AES‑GCM ---
    aes_key = bytes(ss[:32])
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)

    start_aes = time.perf_counter()
    ciphertext = aesgcm.encrypt(nonce, req.plaintext.encode(), None)
    aes_ms = (time.perf_counter() - start_aes) * 1000

    print("##########################KYBER ENCAPSULATION#################################")
    print(f"time_encapsulate_ms: {round(kem_ms, 3)}")
    print("##########################AES ENCRYPTION #################################")
    print(f"time_encrypt_ms: {round(aes_ms, 3)}")

    return {
        "ciphertext_kem": base64.b64encode(bytes(ct)).decode(),
        "ciphertext_data": base64.b64encode(ciphertext).decode(),
        "nonce": base64.b64encode(nonce).decode()
    }

@app.post("/decrypt_data")
def decrypt_data(req: DecryptRequest, token: str = Depends(get_current_token)):
    keys = load_keys()
    if req.did not in keys:
        raise HTTPException(status_code=404, detail="Private key not found")

    kem_ptr = liboqs.OQS_KEM_new(b"Kyber512")
    oqs_kem = OQS_KEM.from_address(kem_ptr)

    sk = base64.b64decode(keys[req.did]["kyber_private_key"])
    ct = base64.b64decode(req.ciphertext_kem)
    ss = (ctypes.c_ubyte * oqs_kem.length_shared_secret)()

    # --- Décapsulation Kyber ---
    start_kem = time.perf_counter()
    liboqs.OQS_KEM_decaps(kem_ptr, ss, ct, sk)
    kem_ms = (time.perf_counter() - start_kem) * 1000
    liboqs.OQS_KEM_free(kem_ptr)

    # --- Déchiffrement AES‑GCM ---
    aes_key = bytes(ss[:32])
    aesgcm = AESGCM(aes_key)

    start_aes = time.perf_counter()
    plaintext_bytes = aesgcm.decrypt(
        base64.b64decode(req.nonce),
        base64.b64decode(req.ciphertext_data),
        None
    )
    aes_ms = (time.perf_counter() - start_aes) * 1000

    print("##########################KYBER DECAPSULATION#################################")
    print(f"time_decapsulate_ms: {round(kem_ms, 3)}")
    print("##########################AES DECRYPTION#################################")
    print(f"time_decrypt_ms: {round(aes_ms, 3)}")
    return plaintext_bytes.decode()