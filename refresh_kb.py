import os
import requests
import faiss
import numpy as np
import json
from datetime import datetime
from openai import OpenAI

# Save paths
INDEX_PATH = "knowledge.index"
META_PATH = "metadata.jsonl"
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

def fetch_reports():
    """
    Fetch daily Sudan reports from OCHA API (or other trusted feeds).
    Example: OCHA humanitarian response updates.
    """
    url = "https://reliefweb.int/updates?advanced-search=(field_country%3A%22Sudan%22)"
    resp = requests.get(url, timeout=30)
    resp.raise_for_status()
    # This is a simplified example, you may need to parse RSS/HTML/JSON properly
    return [resp.text[:2000]]  # keep only short demo text for now

def embed_texts(texts):
    """
    Convert texts to embeddings using OpenAI.
    """
    response = client.embeddings.create(
        model="text-embedding-3-small",
        input=texts
    )
    return [d.embedding for d in response.data]

def update_kb():
    texts = fetch_reports()
    if not texts:
        print("⚠ No new reports fetched.")
        return

    embeddings = embed_texts(texts)

    # Load or create FAISS index
    dim = len(embeddings[0])
    if os.path.exists(INDEX_PATH):
        index = faiss.read_index(INDEX_PATH)
    else:
        index = faiss.IndexFlatL2(dim)

    start_id = index.ntotal
    index.add(np.array(embeddings, dtype="float32"))

    # Save metadata
    with open(META_PATH, "a", encoding="utf-8") as f:
        for i, text in enumerate(texts):
            entry = {"id": start_id + i, "text": text, "date": str(datetime.utcnow())}
            f.write(json.dumps(entry) + "\n")

    faiss.write_index(index, INDEX_PATH)
    print(f"✅ Added {len(texts)} new chunks to KB.")

if __name__ == "__main__":
    update_kb()
