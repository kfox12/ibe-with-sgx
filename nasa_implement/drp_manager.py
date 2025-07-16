#drp_manager.py
import json
def get_exp(identity):
    with open("drp.json") as f:
        all_data = json.load(f)
    for drone in all_data["drones"]:
        if drone["identity"] == identity:
            return drone["wind_xp"]
    raise ValueError(f"Drone with identity {identity} not found")