# coding:utf-8
import pandas as pd
import re
import requests
import psycopg2
import faiss
import numpy as np
import torch
from transformers import AutoTokenizer, AutoModel
from neo4j import GraphDatabase
import transformers
import os
import json
from openai import OpenAI
from py2neo import Graph
import Levenshtein
import time
os.environ["KMP_DUPLICATE_LIB_OK"] = "TRUE"

# ================== 配置 ==================
DEVICE = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
MAX_LENGTH = 256
POOLING = 'first_last_avg'
aa = 0.6
bb = 0.4
cc = 0.6
dd = 0.4

TOPK = 3

# ================== DeepSeek 调用 ==================
client = OpenAI(
    api_key="key",
    base_url="https://api.deepseek.com"
)

# ================== PostgreSQL ===================
conn = psycopg2.connect(
    dbname="rag-type",
    user="postgres",
    password="123456",
    host="localhost",
    port="5432"
)
cur = conn.cursor()

# ================== 一次性缓存 PostgreSQL 数据 ===================
print("📥 Loading cve_node table into memory...")

cur.execute("SELECT cve_id, func_before, ast, description, cwe_id FROM cve_node")
rows = cur.fetchall()

# 构建内存缓存字典
cache = {}
for idx, row in enumerate(rows):
    cache[idx] = {
        "cve_id": row[0],
        "func_before": row[1],
        "ast": row[2],
        "description": row[3],
        "cwe_id": row[4]
    }
print(f"✅ Cached {len(cache)} vulnerability records into memory.\n")

# ================== Neo4j Knowledge Graph (Py2Neo) ===================
graph = Graph("bolt://localhost:7687", auth=("neo4j", "czj10261026"))

def query_cwe_hierarchy(cwe_id: str) -> list[str]:
    """
    查询给定 CWE-ID 的层级路径（祖先->目标）。
    """
    cid_int = int(re.sub(r"\D", "", str(cwe_id)))

    result = graph.run(
        """
        MATCH p = (a:CWE)-[:ChildOf*1..20]->(z:CWE {cweId: $cid})
        RETURN [n IN nodes(p) | n.cweId] AS hierarchy
        ORDER BY length(p) DESC
        LIMIT 1
        """, cid=cid_int
    ).evaluate()
    return [str(x) for x in result] if result else [str(cid_int)]

def build_hierarchy_text(hierarchy):
    """生成层级文本"""
    lines = []
    for i, cid in enumerate(hierarchy):
        node = graph.run("""
            MATCH (n:CWE {cweId: $cid})
            RETURN n.nameEn AS name, n.description AS desc, 
                   n.extendedDescription AS ext, n.commonConsequences AS cons
            LIMIT 1
        """, cid=int(cid)).data()
        prefix = "  -> " if i > 0 else "     "
        if node:
            n = node[0]
            lines.append(
                f"{prefix}CWE-ID: {cid}\n"
                f"     Name: {n.get('name', 'Unknown')}\n"
                f"     Description: {n.get('desc', 'N/A')}\n"
                f"     Extended Description: {n.get('ext', 'N/A')}\n"
                f"     Common Consequences: {n.get('cons', 'N/A')}\n"
            )
    return "".join(lines)

# ================== 加载 FAISS ==================
index_code = faiss.read_index("faiss/faiss_index_code1.index")
index_ast = faiss.read_index("faiss/faiss_index_code2.index")
index_desc = faiss.read_index("faiss/faiss_index_desc.index")

with open("faiss/id_map.json", "r", encoding="utf-8") as f:
    id_map = json.load(f)

def get_vuln_by_idx(idx):
    return cache.get(idx)

# ================== 嵌入模型 ==================
code_model_name = "microsoft/codebert-base"
desc_model_name = "shibing624/text2vec-base-multilingual"

code_tokenizer = AutoTokenizer.from_pretrained(code_model_name)
code_model = AutoModel.from_pretrained(code_model_name).to(DEVICE)
code_model.eval()

desc_tokenizer = AutoTokenizer.from_pretrained(desc_model_name)
desc_model = AutoModel.from_pretrained(desc_model_name).to(DEVICE)
desc_model.eval()

# ================== 向量化 ==================
def embed_text(text, tokenizer, model):
    inputs = tokenizer(text, return_tensors="pt", truncation=True, padding=True, max_length=MAX_LENGTH)
    inputs = {k: v.to(DEVICE) for k, v in inputs.items()}
    with torch.no_grad():
        outputs = model(**inputs, output_hidden_states=True, return_dict=True)
        vec = (outputs.hidden_states[-1] + outputs.hidden_states[1]).mean(dim=1)
    vec = vec.cpu().numpy()[0]
    return vec / np.linalg.norm(vec)

# ================== Jaccard 相似度 ==================
def sim_jaccard(a: str, b: str) -> float:
    """基于词元的 Jaccard 相似度"""
    tokens_a = set(re.findall(r"\w+", a))
    tokens_b = set(re.findall(r"\w+", b))

    return len(tokens_a & tokens_b) / len(tokens_a | tokens_b)

# ================== AST 距离相似度 ==================
# def ast_similarity(ast_a: str, ast_b: str) -> float:
#     """
#     AST 编辑距离相似度：使用 Levenshtein.seqratio
#     范围 [0,1]，越大表示结构越相似。
#     """
#     return Levenshtein.seqratio(ast_a, ast_b)
def ast_similarity(idx_a: np.ndarray, idx_b: int):
    """
    计算两个样本的 AST 向量余弦相似度。
    idx_a: query 对应的临时向量（由 embed_text 生成）
    idx_b: 候选样本在 FAISS 中的索引
    """
    ast_vec_b = index_ast.reconstruct(idx_b)
    return np.dot(idx_a, ast_vec_b).item()

# ================== code rerank ==================
def rerank_by_code_similarity(test_code, test_ast_vec, candidate_data, topk):
    """
    根据 Jaccard + AST 相似度重排
    candidate_data: [(idx, code, ast), ...]
    """
    results = []
    for item in candidate_data:
        idx, code, ast = item
        jacc = sim_jaccard(test_code, code)
        ast_sim = ast_similarity(test_ast_vec, idx)
        score_code = aa * jacc + bb * ast_sim
        results.append({
            "idx": idx,
            "score": score_code
        })

    results = sorted(results, key=lambda x: x["score"], reverse=True)[:topk]
    top_idx = [r["idx"] for r in results]
    top_scores = [r["score"] for r in results]
    return top_idx, top_scores



# ================== RAG 检索 ==================
def rag_search(query_code, query_desc, query_ast):
    code_vec = np.array(embed_text(query_code, code_tokenizer, code_model), dtype='float32').reshape(1, -1)
    desc_vec = np.array(embed_text(query_desc, desc_tokenizer, desc_model), dtype='float32').reshape(1, -1)
    ast_vec = np.array(embed_text(query_ast, code_tokenizer, code_model), dtype='float32').reshape(1, -1)

    _, idx_code = index_code.search(code_vec, TOPK * 2)
    idx_code = idx_code[0].tolist()

    candidate_data = []
    for idx in idx_code:
        vuln = get_vuln_by_idx(idx)
        if vuln:
            candidate_data.append((idx, vuln["func_before"], vuln["ast"]))

    top_idx_code, _ = rerank_by_code_similarity(
        query_code,
        ast_vec[0],  # ✅ 传入 AST 向量
        [(idx, code, ast) for idx, code, ast in candidate_data],
        topk=TOPK
    )


    _, idx_desc = index_desc.search(desc_vec, TOPK)
    idx_desc = idx_desc[0].tolist()

    candidate_idx = list(set(top_idx_code + idx_desc))

    results = []
    for idx in candidate_idx:
        db_code_vec = index_code.reconstruct(idx)
        db_desc_vec = index_desc.reconstruct(idx)
        score = cc * np.dot(code_vec, db_code_vec).item() + dd * np.dot(desc_vec, db_desc_vec).item()
        vuln = get_vuln_by_idx(idx)
        if vuln:
            vuln["score"] = score
            results.append(vuln)

    # 设置RAG检索个数（默认3个）
    k = TOPK

    results = sorted(results, key=lambda x: x["score"], reverse=True)[:k]
    print("==============================================================================================================================")
    for item in results:
        print(f"Score: {item['score']:.4f}, CWE ID: {item['cwe_id']}")
    return results

# ================== DeepSeek + Few-shot COT ==================
def cot_predict_cwe(query_code, query_desc, retrieved_samples):
    prompt = (
        "You are an expert in software vulnerability type classification and CWE analysis. "
        "Your task is to infer the CWE type of the target vulnerability step by step based on similar samples and CWE hierarchy relationships knowledge.\n\n"
    )

    prompt += f"Step 1: Read the context of similar samples and CWE hierarchical relationships.\n"

    for i, s in enumerate(retrieved_samples):
        hierarchy = query_cwe_hierarchy(s["cwe_id"])
        s["hierarchy_text"] = build_hierarchy_text(hierarchy)
        if len(hierarchy) >= 2:
            s["patch"] = f"{hierarchy[-2]}->{hierarchy[-1]}"
        elif len(hierarchy) == 1:
            s["patch"] = hierarchy[0]

        prompt += f"Sample {i + 1}:\n"
        prompt += f"- Code:\n  {s['func_before']}\n"
        prompt += f"- Description:\n  {s['description']}\n"
        prompt += f"- CWE-ID: {s['cwe_id']}\n"
        prompt += f"- Patch: {s.get('patch', 'Unknown')}\n"
        prompt += f"- CWE Hierarchy:\n{s.get('hierarchy_text', '  (No hierarchy found)')}\n\n"


    prompt += f"Step 2: Analyze the aforementioned several similar vulnerability samples.\n"
    prompt += f"For each sample, carefully consider how its code snippet and description map to its corresponding CWE type.\n"
    prompt += f"Identify which aspects of the code and description most clearly reflect the characteristics of the CWE.\n\n"

    prompt += f"Step 3: Analyze the hierarchical relationships corresponding to the CWE types of these samples.\n"
    prompt += f"Analyze the CWE hierarchy for each retrieved sample. For each sample's CWE, review its parent categories and hierarchical links, and reason about the conditions that match this CWE based on its official description, extended description, and common consequences. Specifically, for each CWE, consider:\n"
    prompt += f"- Parent categories\n"
    prompt += f"- Official description\n"
    prompt += f"- Extended description\n"
    prompt += f"Use this hierarchy-aware analysis to judge whether the target vulnerability's code and description fit a narrow, specific CWE or a broader parent CWE.\n\n"

    prompt += f"Step 4: Infer the CWE type of the target vulnerability.\n"
    prompt += f"Target vulnerability:\n"
    prompt += f"- Code: {query_code}\n"
    prompt += f"- Description: {query_desc}\n"
    prompt += f"Compare the target vulnerability with the previous similar samples, focusing on semantic and structural similarity of code and description.\n"
    prompt += f"Combine this with the hierarchical analysis to determine the most likely CWE type of the target vulnerability.\n"
    prompt += f"based on the reasoning in Step 2 and 3.\n\n"


    prompt += f"Step 5: Output only a single specific CWE ID (e.g., CWE-xxx).\n"
    prompt += f"Do not output any reasoning, explanations, or additional text; only the final label should be returned.\n\n"


    # 计算token
    chat_tokenizer_dir = "./deepseek_v3_tokenizer"  # 本地 tokenizer 路径
    tokenizer = transformers.AutoTokenizer.from_pretrained(chat_tokenizer_dir, trust_remote_code=True)
    system_content = "You are an expert in software vulnerability type identification."
    user_content = prompt
    system_tokens = tokenizer.encode(system_content)
    user_tokens = tokenizer.encode(user_content)
    total_tokens = len(system_tokens) + len(user_tokens)
    print("Total tokens:", total_tokens)

    # print(prompt)

    response = client.chat.completions.create(
        model="deepseek-chat",
        messages=[
            {"role": "system", "content": "You are an expert in software vulnerability type identification."},
            {"role": "user", "content": prompt}
        ],
        temperature = 0,
        stream=False
    )

    level = response.choices[0].message.content
    return level


# ================== 主函数 ==================
def predict_cwe_rag_kg_cot(code, desc, ast):
    # RAG 检索 top-K 样本
    samples = rag_search(code, desc, ast)
    # 基于检索样本 + Py2Neo 查询层级进行 COT 推理
    predicted_cwe = cot_predict_cwe(code, desc, samples)
    return predicted_cwe

# ================== 运行入口 ==================
if __name__ == "__main__":
    input_file = "output_dataset/Test_with_ast.csv"
    output_file = "prediction_data/test_predicted_cwe1.csv"
    temp_file = "prediction_data/test_predicted_cwe_temp.csv"


    # output_file_with_set = "prediction_data/test_predicted_cwe_with_set.csv"

    if os.path.exists(output_file):
        df = pd.read_csv(output_file)
        print(f"🔁 继续运行：已加载 {output_file}")
    else:
        df = pd.read_csv(input_file)
        if "Predicted_CWE" not in df.columns:
            df["Predicted_CWE"] = ""
        print(f"🆕 新运行：加载 {input_file}")

    print(df["Predicted_CWE"].unique())
    rows_to_predict = df[
        df["Predicted_CWE"].isna() | (df["Predicted_CWE"].astype(str).str.strip() == "")
        ].index

    if len(rows_to_predict) == 0:
        print("✅ 所有行都已经预测完成！")
    else:
        print(f"🔍 共有 {len(rows_to_predict)} 条样本需要继续预测。")

        for idx in rows_to_predict:
            # time.sleep(1.5)
            row = df.loc[idx]
            code = row.get("func_before", "")
            desc = row.get("description", "")
            ast = row.get("ast", "")

            try:
                pred = predict_cwe_rag_kg_cot(code, desc, ast)
                print(f"[{idx}] Predicted CWE: {pred} (truth: {row['cwe_id']})")
            except Exception as e:
                print(f"❌ Error at row {idx}: {e}")
                pred = ""

            # 写入预测结果
            df.at[idx, "Predicted_CWE"] = pred

            # 保存到临时文件后再覆盖，防止写入中断损坏
            df.to_csv(temp_file, index=False)
            os.replace(temp_file, output_file)

        print(f"✅ 预测完成，结果已保存到 {output_file}")

