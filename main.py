
import requests
import json
import asyncio
import time
import hashlib
import ATTRIBCOST
from indy import pool, wallet, did, ledger, anoncreds, blob_storage
from indy.error import ErrorCode, IndyError
from indy.pairwise import get_pairwise

from os.path import dirname

POOL_NAME = "pool1"
GENESIS_PATH = "pool1.txn"  # À adapter à ton environnement


# URL de base de l'agent PQC
BASE_URL = "http://localhost:80"

# Token JWT/OAuth2 fourni par l'agent
TOKEN = "securetoken"

# Headers pour l'authentification
headers = {
    "Authorization": f"Bearer {TOKEN}",
    "Content-Type": "application/json"
}

# DID utilisé
#didtest = "N9j7eQ1k6UWyAbYStXoeQD"

# 1. Génération ou récupération des clés PQC
def request_pqc_keys(did):
    response = requests.post(
        f"{BASE_URL}/generate_key_pqc",
        headers=headers,
        json={"did": did}
    )
    if response.status_code == 200:
        pqc_keys = response.json()
        #print("✅ PQC-KEYS -  Clés PQC récupérées ou générées avec succès :")
        #pqc_gen_key=json.dumps(pqc_keys)
        #print(json.dumps(pqc_keys, indent=4))
    else:
        print("❌ Erreur lors de la récupération ou génération des clés PQC :", response.text)
        exit()
    return pqc_keys

# 2. Signature PQC d'un message
message = "Mon message important à sécuriser PQC."
def pqc_signature(message, did):
    response = requests.post(
        f"{BASE_URL}/sign_pqc",
        headers=headers,
        json={"did": did, "message": message}
    )

    if response.status_code == 200:
        signature_pqc = response.json()["signature"]
        #print("\n✅ Message signé explicitement en PQC :")
        #print("Signature PQC (base58) :", signature_pqc)
    else:
        print("❌ Erreur lors de la signature PQC :", response.text)
        exit()
    
    return signature_pqc

# 3. Vérification explicite de la signature PQC
def pqc_signature_verification(did, message, signature_pqc):
    #print(f"SIGNATURE :{signature_pqc}")
    response = requests.post(
        f"{BASE_URL}/verify_pqc",
        headers=headers,
        json={"did": did, "message": message, "signature": signature_pqc}
    )

    if (response.status_code == 200) and (response.json()["valid"] == True):
        valid = response.json()["valid"]
        #print("\n✅ Vérification explicite PQC réussie :", valid)
    else:
        print("❌ Erreur lors de la vérification PQC :", response.text)
        exit()
    return valid

# 4. Récupération explicite du DID-Doc PQC
def request_pqc_diddoc(did):
    response = requests.get(
        f"{BASE_URL}/did_doc/{did}",
        headers=headers
    )

    if response.status_code == 200:
        did_doc = response.json()
        print("\n✅ DID-Document PQC :")
        print(json.dumps(did_doc, indent=4))
    else:
        print("❌ Erreur lors de la récupération du DID-Doc PQC :", response.text)
    return did_doc

#Chiffrement
def encrypt_message(did, plaintext):
    response = requests.post(
        f"{BASE_URL}/encrypt_data",
        headers=headers,
        json={"did": did, "plaintext": plaintext}
    )
    #print(f"DID FOR ENCRYPTION : {did}")
    if response.status_code == 200:
        result = response.json()
        #print(f"CHIFFRE RETOURNE : {result}")
        return result
    else:
        raise Exception(f"Encryption failed: {response.text}")
    


#dechiffrement
def decrypt_message( did, ciphertext): #, nonce):
    data = {
        "did": did,
        #"ciphertext": ciphertext,
        "ciphertext_kem":ciphertext.get("ciphertext_kem"),
        "ciphertext_data": ciphertext.get("ciphertext_data"),
        "nonce":ciphertext.get("nonce")
        #"nonce": nonce
    }
    response = requests.post(
        f"{BASE_URL}/decrypt_data",
        json=data,
        headers=headers
    )
    if response.status_code == 200:
        #result = response.json()
        #print(f"TEXTE DECRYPTE RETOURNE : {result['plaintext']}")
        return response.json()#result#['plaintext']
    else:
        raise Exception(f"Decryption failed: {response.text}")



async def setup_pool():
    await pool.set_protocol_version(2)
    try:
        await pool.create_pool_ledger_config(POOL_NAME, json.dumps({"genesis_txn": GENESIS_PATH}))
    except:
        pass
    return await pool.open_pool_ledger(POOL_NAME, None)

async def create_wallet(name, key):
    config = json.dumps({"id": name})
    creds = json.dumps({"key": key})

    try:
        await wallet.delete_wallet(config, creds)
    except:
        pass
    try:
        await wallet.create_wallet(config, creds)
    except:
        pass
    return await wallet.open_wallet(config, creds)



async def create_and_register_did(issuer_wallet, pool_handle, steward_wallet, steward_did, entity):
    new_did, new_verkey = await did.create_and_store_my_did(issuer_wallet, "{}")
    print(f"++++++++++++++++++++++++++++++++++++ DID FOR {entity}+++++++++++++++++++++++++++++++++++++++++")
    print(new_did)
    print(f"++++++++++++++++++++++++++++++++++++ PQC KEYS FOR {entity} +++++++++++++++++++++++++++++++++++++++++")
    print(request_pqc_keys(new_did)) #Creation du PQC de l'entite qui cree le DID
    nym_request = await ledger.build_nym_request(steward_did, new_did, new_verkey, None, "TRUST_ANCHOR")
    await ledger.sign_and_submit_request(pool_handle, steward_wallet, steward_did, nym_request)
    return new_did

async def create_and_publish_schema(issuer_wallet, issuer_did, pool_handle, schema_name, version, attributes):
    schema_id, schema_json = await anoncreds.issuer_create_schema(
        issuer_did, schema_name, version, json.dumps(attributes)
    )
    request = await ledger.build_schema_request(issuer_did, schema_json)
    #print(request)
    #print("===========================REQUETE VERS LA BC========================")
    request_dict = json.loads(request)
    pqc_vc_signature = pqc_signature(request, issuer_did)
    print("++++++++++++++++++++++++++++++++++++SCHEMA PQC SIGNATURE++++++++++++++++++++++++++++++++++++")
    print(str(pqc_vc_signature)) #A publier sur IPFS (Schema ID + Signature)
    # 2. Modifier la requête
    #request_dict["operation"]["data"]["attr_names"].append("email")

    # 3. Reconvertir en chaîne JSON
    request = json.dumps(request_dict)
    #print(request)
    
    await ledger.sign_and_submit_request(pool_handle, issuer_wallet, issuer_did, request)
    return schema_json

async def create_and_publish_cred_def(issuer_wallet, issuer_did, schema_json, pool_handle):
    schema_id = json.loads(schema_json)["id"]

    # 2. Attendre que le schéma soit bien publié et qu'il ait un seqNo
    get_schema_req = await ledger.build_get_schema_request(issuer_did, schema_id)
    get_schema_resp = await ledger.submit_request(pool_handle, get_schema_req)
    _, full_schema_json = await ledger.parse_get_schema_response(get_schema_resp)


    cred_def_id, cred_def_json = await anoncreds.issuer_create_and_store_credential_def(
        issuer_wallet, issuer_did, full_schema_json, "TAG1", "CL", json.dumps({"support_revocation": False})
    )
    request = await ledger.build_cred_def_request(issuer_did, cred_def_json)
    await ledger.sign_and_submit_request(pool_handle, issuer_wallet, issuer_did, request)

    return cred_def_id, cred_def_json

async def prepare_alice():
    #print("++++++++++++++++++++++++++++++Dans Alice++++++++++++++++++++++++++++++++++++")
    alice_wallet = await create_wallet("alice1_wallet", "alice1_key") #avec en parametre le nom du wallet et le mot de passe pour le securiser
    alice_did, _ = await did.create_and_store_my_did(alice_wallet, "{}")
    print("++++++++++++++++++++++++++++++++++++HOLDER DID+++++++++++++++++++++++++++++++++++++++++")
    print(alice_did)
    print("++++++++++++++++++++++++++++++++++++HOLDER PQC KEYS+++++++++++++++++++++++++++++++++++++++++")
    print(request_pqc_keys(alice_did)) #Creation du PQC de l'entite qui cree le DID

    master_secret_id = await anoncreds.prover_create_master_secret(alice_wallet, None)
    return {"wallet": alice_wallet, "did": alice_did, "master_secret_id": master_secret_id}

    
async def issue_credential(agent_wallet, agent_did, cred_def_id, cred_def_json, alice, attributes):
    cred_offer = await anoncreds.issuer_create_credential_offer(agent_wallet, cred_def_id)
    #PQC signe l'offre du credential pour garantir sa protection post quantique
    cred_offer_pqc_sign = pqc_signature(cred_offer, agent_did)
    #print(f"OFFRE SIGNE PQC : {cred_offer_pqc_sign}")
    offer_to_holder={ #c'est cette offre qui est transmise au demandeur du VC
        'offer':cred_offer,
        'offer_signature':cred_offer_pqc_sign,
    }
    #print(f"############################{1}################################")
    #print(offer_to_holder["offer"])
    #Le demandeur du VC valide que l'offre est authentique
    if(pqc_signature_verification(agent_did, offer_to_holder["offer"],offer_to_holder["offer_signature"])):
        #print("SIGNATURE DE OFFRE VERIFIER AVEC SUCCES")
        cred_req, cred_req_meta = await anoncreds.prover_create_credential_req(
            alice["wallet"], alice["did"], offer_to_holder["offer"], cred_def_json, alice["master_secret_id"]
        )
        cred_request_dict = json.loads(cred_req)

        blinded_ms = cred_request_dict["blinded_ms"]
        blinded_ms_proof = cred_request_dict["blinded_ms_correctness_proof"]

        # Convertir explicitement en JSON pour chiffrement
        blinded_ms_json = json.dumps(blinded_ms)
        blinded_ms_proof_json = json.dumps(blinded_ms_proof)
        # Chiffrer explicitement blinded_ms
        print(f"ALICE DID : {alice['did']}")
        #print(blinded_ms_json)
        encrypted_blinded_ms = encrypt_message(agent_did, blinded_ms_json)
        #print("DE RETOUR")
        # Chiffrer explicitement blinded_ms_correctness_proof
        encrypted_blinded_ms_proof = encrypt_message(agent_did, blinded_ms_proof_json)
        print("===============================================BLINDE_MS SIGNATURE++++++++=================================")
        print(encrypted_blinded_ms)
        #cred_request_dict['blinded_ms']=encrypted_blinded_ms
        #cred_request_dict['blinded_ms_correctness_proof']=encrypted_blinded_ms_proof
        cred_request_dict['blinded_ms']['ciphertext']=encrypted_blinded_ms
        cred_request_dict['blinded_ms_correctness_proof']['ciphertext']=encrypted_blinded_ms_proof
#########################################################Envoie a l'agent du Issuer ###################################################################################
        ###########################Agent Issuer dechiffre les champs blinded et la preuve a la reception#######################################33
        cred_nv=json.loads(cred_req)
        cred_nv["blinded_ms"] = json.loads(decrypt_message(agent_did, cred_request_dict['blinded_ms']['ciphertext']))#['plaintext']#.json()
        cred_nv["blinded_ms_proof"]= json.loads(decrypt_message(agent_did, cred_request_dict['blinded_ms_correctness_proof']['ciphertext']))#['plaintext']#.json()
        #########################################l'agent cree le VC ########################################### 
        cred_values = json.dumps({
            k: {"raw": str(v), "encoded": str(abs(hash(v)) % (10**10))}
            for k, v in attributes.items() 
        })
    

        cred_json, _, _ = await anoncreds.issuer_create_credential(
            agent_wallet, offer_to_holder["offer"], json.dumps(cred_nv), cred_values, None, None
        )

        #####################################le issuer signe et applique le chiffrement PQC ypte  de vc avant son envoi a alice ########################
        print("=================================CREDENTIAL OFFERT==============================")
        print(cred_json)
        ##########################################l'Agent signe le VC avant de l'envoyer au Holder#########################################
        #signature PQC
        pqc_vc_signature = pqc_signature(json.dumps(json.loads(cred_json)), agent_did)
        vc_to_holder={
            'vc':json.loads(cred_json),
            'pqc_vc_signature':pqc_vc_signature,
        }
        vc_to_holder_json = json.dumps(vc_to_holder)
        cred_json_chiffre=encrypt_message(alice["did"], vc_to_holder_json)

############################################Alice Reception le VC, le decrypte et verifie la signature  holder##########################################################
        #print("+++++++++++++++++++++++++++++++++++++ICI++++++++++++++++++++++++")
        cred_json_dechiffre = json.loads(decrypt_message(alice["did"], cred_json_chiffre))
        #alice['transcript_cred'] = vc_to_holder
        classi_vc=json.dumps(json.loads(json.dumps(cred_json_dechiffre['vc'])))

        if pqc_signature_verification(agent_did, classi_vc, cred_json_dechiffre['pqc_vc_signature']) :
            await anoncreds.prover_store_credential(
                alice["wallet"], None, cred_req_meta, json.dumps(cred_json_dechiffre['vc']), cred_def_json, None
            )
            #print("================================**************************************=========================================")
            #print("CREDENTIAL RECU ET ENREGISTRE")
            return cred_json




async def fetch_schema_and_cred_def(pool_handle, submitter_did, credential_info):
    schema_id = credential_info['schema_id']
    cred_def_id = credential_info['cred_def_id']

    schema_req = await ledger.build_get_schema_request(submitter_did, schema_id)
    schema_resp = await ledger.submit_request(pool_handle, schema_req)
    _, schema_json = await ledger.parse_get_schema_response(schema_resp)
    #schema = json.loads(schema_json)
    #schema_seq_no = schema["seqNo"]
    #cred_def_id = f"{cred_def_id.split(':', 1)[0]}:3:CL:{schema_seq_no}:TAG1"

    #print("++++++++++++++++CREDENTIAL ID ++++++++++++++++++")
    #print(cred_def_id)
    cred_def_req = await ledger.build_get_cred_def_request(submitter_did, cred_def_id)
    cred_def_resp = await ledger.submit_request(pool_handle, cred_def_req)
    _, cred_def_json = await ledger.parse_get_cred_def_response(cred_def_resp)

    return schema_id, json.loads(schema_json), cred_def_id, json.loads(cred_def_json)


def get_proof_request_models():
    #CECI devrait egalement etre signe avec dilitium avant transmission a Alice

    return [
        {
            "nonce": "1234567890000000002",
            "name": "Proof of Work Experience",
            "version": "1.0",
            "requested_attributes": {
                "attr1_referent": { "name": "name", "restrictions": [] },
                "attr2_referent": { "name": "position", "restrictions": [] }
            },
            "requested_predicates": {
                "predicate1_referent": {
                "name": "duration",
                "p_type": ">=",
                "p_value": 5,
                "restrictions": []
                }
            }
            },

            {
            "nonce": "1234567890000000001",
            "name": "Proof of Academic Qualification",
            "version": "1.0",
            "requested_attributes": {
                "attr1_referent": { "name": "name", "restrictions": [] },
                "attr2_referent": { "name": "degree", "restrictions": [] }
            },
            "requested_predicates": {}
        }

    ]

async def alice_create_presentation(wallet_handle, pool_handle, alice_did, proof_request_json, master_secret_id):
    search_handle = await anoncreds.prover_search_credentials_for_proof_req(wallet_handle, proof_request_json, None)
    #print("++++++++++++++++++++++++Search Handle+++++++++++++++++++++++++")
    #print(search_handle)
    proof_request = json.loads(proof_request_json)
    collected = {}
    schemas = {}
    cred_defs = {}

    for attr_ref in proof_request["requested_attributes"]:
        creds_json = await anoncreds.prover_fetch_credentials_for_proof_req(search_handle, attr_ref, 10)
        creds = json.loads(creds_json)
        if not creds:
            await anoncreds.prover_close_credentials_search_for_proof_req(search_handle)
            return None
        collected[attr_ref] = creds[0]
        cred_info = creds[0]["cred_info"]
        s_id, s_json, c_id, c_json = await fetch_schema_and_cred_def(pool_handle, alice_did, cred_info)
        schemas[s_id] = s_json
        cred_defs[c_id] = c_json

    for pred_ref in proof_request.get("requested_predicates", {}):
        try:
            #print("++++++++++++++++ Pour le predicat ++++++++++++++++")
            #print(pred_ref)
            creds_json = await anoncreds.prover_fetch_credentials_for_proof_req(search_handle, pred_ref, 10)
            creds = json.loads(creds_json)
            if not creds:
                await anoncreds.prover_close_credentials_search_for_proof_req(search_handle)
                print(f"❌ No credential satisfy the predicate  {pred_ref}")
                return None
            collected[pred_ref] = creds[0]
            cred_info = creds[0]["cred_info"]
            s_id, s_json, c_id, c_json = await fetch_schema_and_cred_def(pool_handle, alice_did, cred_info)
            schemas[s_id] = s_json
            cred_defs[c_id] = c_json
        except Exception as e:
            print(f"❌ Erreur sur {pred_ref} :", e)
            continue


    await anoncreds.prover_close_credentials_search_for_proof_req(search_handle)

    requested_credentials = {
        "self_attested_attributes": {},
        "requested_attributes": {
            k: {"cred_id": v["cred_info"]["referent"], "revealed": True}
            for k, v in collected.items() if k.startswith("attr")
        },
        "requested_predicates": {
            k: {"cred_id": v["cred_info"]["referent"]}
            for k, v in collected.items() if k.startswith("predicate")
        }
    }

    presentation = await anoncreds.prover_create_proof(
        wallet_handle,
        proof_request_json,
        json.dumps(requested_credentials),
        master_secret_id,
        json.dumps(schemas),
        json.dumps(cred_defs),
        json.dumps({})
    )
    return presentation

def verifier_verify_proof(proof_request_json, presentation_json):
    print("\n📥 VP Received :")
    print(json.dumps(json.loads(presentation_json), indent=2))
    print("\n✅ VP Accepted ")


async def extract_credentials_from_wallet(wallet_handle):
    #wallet_handle = await wallet.open_wallet(wallet_config, wallet_credentials)
    credentials = []
    search_handle = await anoncreds.prover_search_credentials(wallet_handle, "{}")

    while True:
        batch_json = await anoncreds.prover_fetch_credentials(search_handle, 10)
        batch = json.loads(batch_json)
        if not batch:
            break
        for cred in batch:
            cred_attrs = cred["cred_info"]["attrs"]
            credentials.append({ "attrs": cred_attrs })

    await anoncreds.prover_close_credentials_search(search_handle)
    await wallet.close_wallet(wallet_handle)
    return credentials


async def main():
    pool_handle = await setup_pool()

    # Steward (utilisé pour inscrire les DIDs)
    steward_wallet = await create_wallet("steward_wallet", "steward_key")
    steward_did_info = json.dumps({"seed": "000000000000000000000000Steward1"})
    steward_did, _ = await did.create_and_store_my_did(steward_wallet, steward_did_info)
    request_pqc_keys(steward_did) #Creation de la PQC du steward
    #print(f" steward DID {steward_did}" )
    #print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
    # Préparer le portefeuille utilisateur Alice
    alice = await prepare_alice()
    #print("+++++++++++++++++++++++++++++OK Alice++++++++++++++++++++++++++++++++++++")
    # Définir les agents
    agents = [
        {
            "name": "university",
            "schema": ("DiplomaSchema", "1.0", ["name", "degree", "graduation_date"]),
            "data": {
                "name": "Alice Dupont",
                "degree": "Master's in Computer Science",
                "graduation_date": "2023-06-30"
            }
            },
            {
            "name": "city_hall",
            "schema": ("ResidenceSchema", "1.0", ["name", "date_of_birth",  "address", "issue_date"]),
            "data": {
                "name": "Alice Dupont",
                "date_of_birth": "1992-01-15",
                "address": "123 Rue de Rivoli, 75001 Paris",
                "issue_date": "2025-01-15"
            }
            },
            {
            "name": "prefecture",
            "schema": ("LicenseSchema", "1.0", ["name", "license_number", "categories", "issue_date", "expiration"]),
            "data": {
                "name": "Alice Dupont",
                "license_number": "99ABC4567",
                "categories": "B, BE",
                "issue_date": "2022-04-12",
                "expiration": "2032-04-12"
            }
            },
            {
            "name": "company",
            "schema": ("EmploymentSchema", "1.0", ["name", "position", "duration"]),
            "data": {
                "name": "Alice Dupont",
                "position": "Software Developer",
                "duration": 6
            }
        }

    ]

    # Traiter chaque agent
    ##############################################cette section correspond a la collecte et la sauvegrade des credentials ###################################
    for agent in agents:
        wallet_name = f"{agent['name']}_wallet"
        #print(f"++++++++++++++++++====={wallet_name}")
        wallet_key = f"{agent['name']}_key"
        #print(f"++++++KEY+++++++++====={wallet_key}")
        agent_wallet = await create_wallet(wallet_name, wallet_key)
        agent_did = agent_did = await create_and_register_did(agent_wallet, pool_handle, steward_wallet, steward_did,agent['name'] )
        schema_json = await create_and_publish_schema(agent_wallet, agent_did, pool_handle, *agent["schema"])
        print(f"++++++++++++++++++++++++++++++++++++++++++++{agent['name']} SCHEMA++++++++++++++++++++++++++++")
        print(schema_json)

        cred_def_id, cred_def_json = await create_and_publish_cred_def(agent_wallet, agent_did, schema_json, pool_handle)
        print(f"++++++++++++++++++++++++++++++++++++++++++++{agent['name']} CREDENTIAL DEFINITION ++++++++++++++++++++++++++++")
        print(cred_def_json)
        vc = await issue_credential(agent_wallet, agent_did, cred_def_id, cred_def_json, alice, agent["data"])

        print(f"++++++++++++++++++++++++++++++++++++++++++++VC OF {agent['name']} SEND TO HOLDER ++++++++++++++++++++++++++++")
        print(vc)
        #print(f"\nVC OF {agent['name']} SEND TO :\n{vc}\n")
        await wallet.close_wallet(agent_wallet)

    #print("+++++++++++++++++++++++++++++++++++++++++Alice+++++++++++++++++++++++++++++++++++++++++")
    #print(alice)
    creds = await anoncreds.prover_get_credentials(alice["wallet"], "{}")

    # Parser la réponse JSON
    cred_list = json.loads(creds)

    print(f"\n+++++++++++++++++++++++++++++++++++++++HOLDER OWNS {len(cred_list)} CREDENTIAL(S)  +++++++++++++++++++++++++++++++++++++++")
    for idx, cred in enumerate(cred_list):
        print(f"\n--- Verifiable Credential {idx+1} ---")
        for attr in cred["attrs"]:
            print(f"{attr}: {cred['attrs'][attr]}")


    ######################################Creation et prsentation du Verified presentation #################################
    proof_requestsvp = get_proof_request_models()
    print("+++++++++++++++++++++++++++++++++++++++PROOF REQUEST  SEND BY VERIFIER+++++++++++++++++++++++++++++++++++++++.\n")
    print(proof_requestsvp)
    temp = await ATTRIBCOST.return_proof_optimise_request(proof_requestsvp, alice["wallet"])

    #print("+++++++++++++++++++++++++++++++++++++++RECOMMANDED PROOF TO HOLDER+++++++++++++++++++++++++++++++++++++++.\n")
    #print(temp)
    proof_requests=[temp]

    for model in proof_requests:
        #print(f"🔎 Verifier propose : {model['name']}")
        proof_request_json = json.dumps(model)
        print("++++++++++++++++++++++++++++++++++++++++++RECOMMENDED PROOF REQUEST +++++++++++++++++++++++++")
        #print(model)
        print(proof_request_json)
        ############################################A LEMISSION DU VP########################################################
        presentation = await alice_create_presentation(alice["wallet"], pool_handle, alice["did"], proof_request_json, alice["master_secret_id"])
        if presentation:
            #print("📦 Alice a généré une présentation.")
            #verifier_verify_proof(proof_request_json, presentation)
            pqc_vp_signature = pqc_signature(json.dumps(json.loads(presentation)), alice["did"])
            vp_to_verifier={
                'vp':json.loads(presentation),
                'pqc_vp_signature':pqc_vp_signature,
            }
            ###########################################alice["did"] doit [etre remplace par le DID du Verifier ##############################]
            #print("+++++++++++++++++++++++++++++++++AVANT VERIFICATION DU VP+++++++++++++++++++++++++++++++++++")
            vp_to_verifier_json = json.dumps(vp_to_verifier)
            print("++++++++++++++++++++++++++++++++++++++++++VP SEND TO VERIFIER (BEFORE ENCRYPTION) +++++++++++++++++++++++++")
            print(vp_to_verifier_json)

            vp_json_chiffre=encrypt_message(alice["did"], vp_to_verifier_json)
            print("++++++++++++++++++++++++++++++++++++++++++ENCRYPTED VP SEND TO VERIFIER  +++++++++++++++++++++++++")
            print(vp_json_chiffre)

            ####################################A LA RECEPTION DU VP##############################################################
            #print("+++++++++++++++++++++++++++++++++++++A LA RECEPTION DU VP++++++++++++++++++++++++")
            vp_json_dechiffre = json.loads(decrypt_message(alice["did"], vp_json_chiffre))
                #alice['transcript_cred'] = vc_to_holder
            classi_vp=json.dumps(json.loads(json.dumps(vp_json_dechiffre['vp'])))

            if pqc_signature_verification(alice["did"], classi_vp, vp_json_dechiffre['pqc_vp_signature']) :
                print("++++++++++++++++++++++++++++++++++++++++++VP RECIEVED BY VERIFIER++++++++++++++++++++++++++++++")
                print(classi_vp)
                print("++++++++++++++++++++++++++++++++++++++++++ACCESS AUTORISED++++++++++++++++++++++++++++++")
                
            break
        else:
            print("❌ Aucun credential compatible pour ce modèle. Passage au suivant...\n")


        
            

    #print(f"+====================WALLET CONTAINS===================================")
    #print(await extract_credentials_from_wallet(alice["wallet"]))





    # Nettoyage
    await wallet.close_wallet(alice["wallet"])
    await wallet.close_wallet(steward_wallet)
    await pool.close_pool_ledger(pool_handle)

loop = asyncio.get_event_loop()
loop.run_until_complete(main())

