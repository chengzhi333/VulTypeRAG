# coding:utf-8
import psycopg2
import json
import pandas as pd
import numpy as np
import torch
from transformers import AutoTokenizer, AutoModel
import faiss
from tqdm import tqdm
import os

# ================== 配置 ===================
DEVICE = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
MAX_LENGTH = 256
POOLING = 'first_last_avg'

# ================== 数据库 ===================
conn = psycopg2.connect(
    dbname="rag-type",
    user="postgres",
    password="123456",
    host="localhost",
    port="5432"
)
cur = conn.cursor()

# ================== 建表 ===================
def ensure_schema():
    with conn.cursor() as cur:
        cur.execute("CREATE EXTENSION IF NOT EXISTS vector;")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS cve_node (
                cve_id TEXT,
                func_before TEXT,
                ast TEXT,
                description TEXT,
                cwe_id TEXT,
                code_embedding1 VECTOR(768),  -- 源代码向量
                code_embedding2 VECTOR(768),  -- AST向量
                desc_embedding VECTOR(384)    -- 描述向量
            );
        """)
        conn.commit()
    print("✅ 数据表 cve_node 已准备完毕")

# ================== 清空旧数据 ===================
def clear_table():
    with conn.cursor() as cur:
        cur.execute("TRUNCATE TABLE cve_node;")
    conn.commit()
    print("⚙️ 已清空旧数据")

# ================== 模型 ===================
code_model_name = "microsoft/codebert-base"
desc_model_name = "shibing624/text2vec-base-multilingual"

code_tokenizer = AutoTokenizer.from_pretrained(code_model_name)
code_model = AutoModel.from_pretrained(code_model_name).to(DEVICE)
code_model.eval()

desc_tokenizer = AutoTokenizer.from_pretrained(desc_model_name)
desc_model = AutoModel.from_pretrained(desc_model_name).to(DEVICE)
desc_model.eval()

# ================== 向量化函数 ===================
def embed_text(text, tokenizer, model):
    if not isinstance(text, str) or not text.strip():
        text = "empty"
    inputs = tokenizer(text, return_tensors="pt", truncation=True, padding=True, max_length=MAX_LENGTH)
    inputs = {k: v.to(DEVICE) for k, v in inputs.items()}
    with torch.no_grad():
        outputs = model(**inputs, output_hidden_states=True, return_dict=True)
        hidden_states = outputs.hidden_states
        if POOLING == 'first_last_avg':
            vec = (hidden_states[-1] + hidden_states[1]).mean(dim=1)
        elif POOLING == 'last_avg':
            vec = hidden_states[-1].mean(dim=1)
        elif POOLING == 'last2avg':
            vec = (hidden_states[-1] + hidden_states[-2]).mean(dim=1)
        else:
            raise Exception(f"Unknown pooling {POOLING}")
    vec = vec.cpu().numpy()[0]
    vec = vec / np.linalg.norm(vec)
    return vec.tolist()

def embed_code(text):
    return embed_text(text, code_tokenizer, code_model)

def embed_desc(text):
    return embed_text(text, desc_tokenizer, desc_model)

# ================== 主程序 ===================
def main():
    ensure_schema()
    clear_table()
    df = pd.read_csv("output_dataset/Train_with_ast.csv")

    code_vectors1, code_vectors2, desc_vectors = [], [], []
    id_map = {}

    print(f"[INFO] 总样本数: {len(df)}")

    for idx, row in tqdm(df.iterrows(), total=len(df), desc="Embedding"):
        cve_id = str(row.get("cve_id", "")).strip()
        func_before = str(row.get("func_before", "")).strip()
        ast = str(row.get("ast", "")).strip()
        description = str(row.get("description", "")).strip()
        cwe_id = str(row.get("cwe_id", "")).strip()

        # 向量化
        code_vec1 = embed_code(func_before)
        code_vec2 = embed_code(ast)
        desc_vec = embed_desc(description)
        code_vectors1.append(code_vec1)
        code_vectors2.append(code_vec2)
        desc_vectors.append(desc_vec)

        # 插入数据库（新增 ast 字段）
        cur.execute("""
                    INSERT INTO cve_node 
                    (cve_id, func_before, ast, description, cwe_id, code_embedding1, code_embedding2, desc_embedding)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING cve_id
                """, (cve_id, func_before, ast, description, cwe_id, code_vec1, code_vec2, desc_vec))
        conn.commit()

        id_map[idx] = cve_id

    print("[INFO] 向量化完成，开始构建FAISS索引...")

    # 转换为numpy
    code_np1 = np.array(code_vectors1, dtype='float32')
    code_np2 = np.array(code_vectors2, dtype='float32')
    desc_np = np.array(desc_vectors, dtype='float32')

    # 构建FAISS索引
    index_code1 = faiss.IndexFlatL2(code_np1.shape[1])
    index_code1.add(code_np1)

    index_code2 = faiss.IndexFlatL2(code_np2.shape[1])
    index_code2.add(code_np2)

    index_desc = faiss.IndexFlatL2(desc_np.shape[1])
    index_desc.add(desc_np)

    # 保存索引
    os.makedirs("faiss", exist_ok=True)
    faiss.write_index(index_code1, "faiss/faiss_index_code1.index")
    faiss.write_index(index_code2, "faiss/faiss_index_code2.index")
    faiss.write_index(index_desc, "faiss/faiss_index_desc.index")

    # 保存id_map
    with open("faiss/id_map.json", "w", encoding="utf-8") as f:
        json.dump(id_map, f, indent=2, ensure_ascii=False)

    print("✅ 全部完成！FAISS索引和id_map已生成。")

if __name__ == "__main__":
    main()
    cur.close()
    conn.close()
