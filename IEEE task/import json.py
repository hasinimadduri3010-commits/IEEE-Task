import json

data = {
    "sample.txt": "ABC123"
}

with open("hashes.json", "w") as file:
    json.dump(data, file, indent=4)