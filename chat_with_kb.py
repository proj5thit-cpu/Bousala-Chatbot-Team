# chat_with_kb.py
import os
import json
import faiss
import numpy as np
from dotenv import load_dotenv
from openai import OpenAI

# ========================
# Load API Key
# ========================
load_dotenv()
API_KEY = os.getenv("OPENAI_API_KEY")
if not API_KEY:
    raise RuntimeError("❌ OPENAI_API_KEY not set in .env")

client = OpenAI(api_key=API_KEY)

# ========================
# Load FAISS index + metadata
# ========================
INDEX_PATH = "knowledge.index"
META_PATH = "metadata.jsonl"


def load_metadata(path=META_PATH):
    metadata = []
    if not os.path.exists(path):
        raise FileNotFoundError(f"❌ Metadata file not found: {path}")
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            try:
                metadata.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return metadata


print("🔎 Loading FAISS index and metadata...")
index = faiss.read_index(INDEX_PATH)
metadata = load_metadata()
print(f"✅ Loaded {len(metadata)} metadata entries")


# ========================
# Semantic Search
# ========================
def search_index(query, k=3):
    resp = client.embeddings.create(
        model="text-embedding-3-small",
        input=query
    )
    q_emb = np.array(resp.data[0].embedding, dtype="float32").reshape(1, -1)
    D, I = index.search(q_emb, k)

    results = []
    for idx, score in zip(I[0], D[0]):
        if 0 <= idx < len(metadata):
            results.append({"score": float(score), **metadata[idx]})
    return results


# ========================
# Answer with Context
# ========================
def answer_with_context(query, k=3):
    hits = search_index(query, k)
    if not hits:
        return "❌ Sorry, no relevant info found.", []

    context = "\n\n".join([h["text"] for h in hits])
    prompt = (
        "You are a helpful assistant. Use the context below to answer.\n\n"
        f"Context:\n{context}\n\n"
        f"Question: {query}\nAnswer:"
    )

    resp = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": prompt}]
    )
    answer = resp.choices[0].message.content
    return answer, hits


# ========================
# Run CLI
# ========================
if __name__ == "__main__":
    while True:
        q = input("\nAsk something (or 'quit'): ").strip()
        if q.lower() in {"quit", "exit"}:
            break
        ans, refs = answer_with_context(q)
        print("\n🤖 Answer:", ans)
        print("\n📌 Sources:")
        for r in refs:
            print(f"- {r['filename']} (score={r['score']:.4f})")
