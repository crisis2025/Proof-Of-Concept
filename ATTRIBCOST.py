import json
import requests
import asyncio
import os
from indy import wallet, anoncreds

# Configuration du wallet d’Alice
WALLET_CONFIG = json.dumps({ "id": "alice1_wallet" })
WALLET_CREDENTIALS = json.dumps({ "key": "alice1_key" })

# API VP
API_URL = "http://localhost:8000/select_vp"

# Extraction des credentials du wallet
async def extract_credentials_from_wallet(wallet_handle):
    #wallet_handle = await wallet.open_wallet(wallet_config, wallet_credentials)

    credentials = []
    search_handle, _ = await anoncreds.prover_search_credentials(wallet_handle, "{}")


    while True:
        batch_json = await anoncreds.prover_fetch_credentials(search_handle, 10)
        batch = json.loads(batch_json)
        if not batch:
            break
        for cred in batch:
            cred_attrs = cred["attrs"]
            credentials.append({ "attrs": cred_attrs })

    await anoncreds.prover_close_credentials_search(search_handle)
    #await wallet.close_wallet(wallet_handle)
    
    return credentials


def store_attribute_mapping_with_cost(credential_list: list, cost_values: dict, filepath="attribute_mapping.json"):
    """
    Prend une liste de credentials (format issu du wallet),
    stocke/complète le mapping {nom: aX} et le coût {aX: value}.
    
    :param credential_list: liste de dicts comme [{'attrs': {...}}, ...]
    :param cost_values: dict {nom: 3, diplome: 3, ...}
    :param filepath: fichier JSON de sortie
    """
    # Charger ou initialiser le fichier
    if os.path.exists(filepath):
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, dict) or "mapping" not in data or "cost" not in data:
                data = {"mapping": {}, "cost": {}}
        except Exception:
            data = {"mapping": {}, "cost": {}}
    else:
        data = {"mapping": {}, "cost": {}}

    current_index = len(data["mapping"]) + 1

    for cred in credential_list:
        attrs = cred.get("attrs", {})
        for attr in attrs:
            if attr not in data["mapping"]:
                short_code = f"a{current_index}"
                data["mapping"][attr] = short_code
                current_index += 1

            short = data["mapping"][attr]
            cost = cost_values.get(attr, 1)
            data["cost"][short] = cost

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    #print(f"✅ Mapping mis à jour dans {filepath}")
    return data

# Construction et appel de l'API VP
async def Store_maping(credentials):
    impact = {
            "name": 3,     
            "date_of_birth": 7,            
            "degree": 6,               
            "graduation_date": 3,      
            "address": 3,              
            "issue_date": 3,           
            "license_number": 3,       
            "categories": 3,           
            "license_issue_date": 3,   
            "expiration": 3,           
            "position": 2,             
            "duration": 3         
            }

    store_attribute_mapping_with_cost(credentials, impact)
    #print(credentials)

def build_and_call_vp_api( credentials, proof_request: dict, mapping_file="attribute_mapping.json", url="http://localhost:8080/select_vp"):
    """
    Construit le payload attendu par l'agent VP, en extrayant :
    - le mapping attribut → aX
    - les coûts associés
    Appelle ensuite l'agent FastAPI et affiche la réponse.
    """
    
    # Charger le mapping et les coûts
    with open(mapping_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    attribute_mapping = data.get("mapping", {})
    disclosure_cost = data.get("cost", {})

    # Construire le payload
    payload = {
        "disclosure_cost": disclosure_cost,
        "attribute_mapping": attribute_mapping,
        "credentials": credentials,
        "proof_request": proof_request
    }

    # Appeler l'API
    try:
        response = requests.post(url, json=payload)
        if response.status_code == 200:
            result = response.json()
            #print("++++++++++++++++++++++++++++++++PROOF REQUEST+++++++++++++++++++++++++++++++")
            #print(result["proof_request"])
            print("++++++++++++++++++++++++++++++++RECOMMENDED ATTRIBUTES ++++++++++++++++++++++++++++++++++++++++++++")
            print("✅ Attributes :", result["disclosed_attributes"])
            print("💰 Total Cost/Risk :", result["total_cost"])
            
            return result
        else:
            print("❌ Erreur HTTP :", response.status_code)
            print(response.text)
            return None
    except Exception as e:
        print("❌ Erreur lors de l'appel à l'API :", e)
        return None    

async def return_proof_optimise_request( vp_proofrequest, wallet_handle):
    credentials = await extract_credentials_from_wallet(wallet_handle)
    await Store_maping(credentials)
    result= build_and_call_vp_api(credentials, vp_proofrequest)
    return result["proof_request"]



