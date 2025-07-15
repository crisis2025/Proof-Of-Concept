# Agent SSI : Optimiseur de Verifiable Presentation (VP)
# Exposé en tant qu'API FastAPI : reçoit les VC, les coûts de divulgation et une liste de proof_requests,
# puis retourne le meilleur proof_request que le détenteur peut satisfaire en minimisant la divulgation.

from z3 import *
from fastapi import FastAPI
from pydantic import BaseModel
from typing import Dict, List, Any
from fastapi.responses import JSONResponse
import uvicorn
import time 

app = FastAPI()

class VpSelectorAgent:
    def __init__(self, disclosure_cost, attribute_mapping):
        self.disclosure_cost = disclosure_cost
        self.attributes = list(disclosure_cost.keys())
        self.attribute_mapping = attribute_mapping

    def extract_wallet_attributes(self, credentials):
        present = set()
        for cred in credentials:
            attrs = cred.get("attrs", {})
            for attr in attrs:
                mapped = self.attribute_mapping.get(attr)
                if mapped:
                    present.add(mapped)
        return sorted(list(present))

    def extract_request_families_with_objects(self, proof_requests: list) -> List[Dict[str, Any]]:
        families = []
        for req in proof_requests:
            group = []
            for attr_data in req.get("requested_attributes", {}).values():
                name = attr_data.get("name")
                mapped = self.attribute_mapping.get(name)
                if mapped and mapped not in group:
                    group.append(mapped)
            for pred_data in req.get("requested_predicates", {}).values():
                name = pred_data.get("name")
                mapped = self.attribute_mapping.get(name)
                if mapped and mapped not in group:
                    group.append(mapped)
            if group:
                families.append({"group": sorted(group), "request": req})
        return families

    def select_best_proof_request(self, wallet_attrs: List[str], request_families: List[Dict[str, Any]]) -> Dict[str, Any]:
        best_cost = float('inf')
        best_request_obj = None
        best_disclosure = None
        best_group = None

        from itertools import chain, combinations

        def all_subsets(lst):
            return chain.from_iterable(combinations(lst, r) for r in range(1, len(lst)+1))

        for candidate in all_subsets(wallet_attrs):
            candidate_set = set(candidate)
            for entry in request_families:
                group = entry["group"]
                request_obj = entry["request"]
                if set(group).issubset(candidate_set):
                    cost = sum(self.disclosure_cost.get(a, 0) for a in candidate_set)
                    if cost < best_cost:
                        best_cost = cost
                        best_request_obj = request_obj
                        best_disclosure = {a: True for a in candidate_set}
                        best_group = group
        if best_request_obj:
            return {
                "satisfiable": True,
                "proof_request": best_request_obj,
                "vp_attributes": best_group,
                "disclosed_attributes": best_disclosure,
                "total_cost": best_cost
            }
        else:
            return {"satisfiable": False}

class SelectVpRequest(BaseModel):
    disclosure_cost: Dict[str, int]
    attribute_mapping: Dict[str, str]
    credentials: List[Dict[str, Any]]
    proof_request: List[Dict[str, Any]]

@app.post("/select_vp")
async def select_vp(request_data: SelectVpRequest):
    agent = VpSelectorAgent(
        request_data.disclosure_cost,
        request_data.attribute_mapping
    )
    wallet_attrs = agent.extract_wallet_attributes(request_data.credentials)
    request_families = agent.extract_request_families_with_objects(request_data.proof_request)
    start_optimisation_time=time.perf_counter()
    result = agent.select_best_proof_request(wallet_attrs, request_families)
    optimisation_time = (time.perf_counter() - start_optimisation_time) * 1000
    print("#####################################TEMPS DE SELECTION OPTIMALE PAR AGEENT SMT ##################################################")
    print(f"Selection Optimale en : {round(optimisation_time, 3)}")
    print("#####################################END DE SELECTION OPTIMALE PAR AGENT SMT ##################################################")
    return JSONResponse(result)

#if __name__ == "__main__":
#    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
