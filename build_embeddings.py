# build_embeddings.py
import os
import json
import faiss
import numpy as np
from dotenv import load_dotenv
from openai import OpenAI

# ========================
# Load API key
# ========================
load_dotenv()
API_KEY = os.getenv("OPENAI_API_KEY")
if not API_KEY:
    raise RuntimeError("❌ OPENAI_API_KEY not set in .env")

client = OpenAI(api_key=API_KEY)

# Folder for knowledge base files
knowledge_folder = "knowledge_base/"   # adjust if needed

# Allowed text file extensions
TXT_EXTS = {".txt", ".md", ".html", ".json", ".csv"}


# ========================
# Step 1: Load Documents
# ========================
def load_documents(folder_path):
    docs = []
    if not os.path.isdir(folder_path):
        return docs
    for root, _, files in os.walk(folder_path):
        for fn in files:
            ext = os.path.splitext(fn)[1].lower()
            if ext in TXT_EXTS:
                path = os.path.join(root, fn)
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        txt = f.read().strip()
                        if txt:
                            relpath = os.path.relpath(path, folder_path)
                            docs.append((relpath, txt))
                except Exception as e:
                    print(f"⚠️ Could not read {path}: {e}")
    return docs


# ========================
# Step 2: Split into Chunks
# ========================
def chunk_text(text, max_chars=800, overlap=100):
    chunks = []
    start = 0
    L = len(text)
    while start < L:
        end = min(start + max_chars, L)
        chunk = text[start:end].strip()
        if chunk:
            chunks.append(chunk)
        start += max_chars - overlap
    return chunks


# ========================
# Step 3: Build Embeddings
# ========================
def build_embeddings(documents):
    chunks = []
    for filename, content in documents:
        for c in chunk_text(content):
            chunks.append((filename, c))

    if not chunks:
        print("❌ No chunks to embed.")
        return

    embeddings = []
    metadata = []
    print(f"🔎 Creating embeddings for {len(chunks)} chunks...")

    for idx, (filename, chunk) in enumerate(chunks, 1):
        try:
            resp = client.embeddings.create(
                model="text-embedding-3-small",
                input=chunk
            )
            emb = resp.data[0].embedding
            embeddings.append(np.array(emb, dtype="float32"))
            metadata.append({"filename": filename, "text": chunk})
        except Exception as e:
            print(f"⚠️ Embedding failed for {filename} (chunk {idx}): {e}")

    if not embeddings:
        print("❌ No embeddings created.")
        return

    embeddings_array = np.vstack(embeddings).astype("float32")

    dim = embeddings_array.shape[1]
    index = faiss.IndexFlatL2(dim)
    index.add(embeddings_array)

    # Save FAISS index
    faiss.write_index(index, "knowledge.index")
    print("✅ Saved knowledge.index")

    # Save metadata as JSONL
    with open("metadata.jsonl", "w", encoding="utf-8") as f:
        for m in metadata:
            f.write(json.dumps(m, ensure_ascii=False) + "\n")

    print(f"✅ Created embeddings for {len(metadata)} chunks and saved metadata.jsonl")


# ========================
# Run Script
# ========================
if __name__ == "__main__":
    docs = load_documents(knowledge_folder)
    if not docs:
        print("❌ No documents found in", knowledge_folder)
    else:
        build_embeddings(docs)
