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
import transformers
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

# tokenizer（用于统计 token 数）
CHAT_TOKENIZER_DIR = "./deepseek_v3_tokenizer"

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

# ================== Prompt 模板（system + user） ==================
SYSTEM_CONTENT = (
    "You are an expert in software vulnerability type identification."
)

# ================== DeepSeek + Few-shot COT ==================
def build_cwe_rag_cot_prompt(query_code, query_desc, retrieved_samples, tokenizer):
    """
    构建 RAG + Few-shot COT prompt，并统计 token 细分结构：
        - 每个样本的Token数（Code, Description, CWE-ID, Patch）
        - 每个样本的CWE层级链路 Token 数
    """
    prompt = (
        "You are an expert in software vulnerability type classification and CWE analysis. "
        "Your task is to infer the CWE type of the target vulnerability step by step based on similar samples and CWE hierarchy relationships knowledge.\n\n"
    )

    prompt += f"Step 1: Read the context of similar samples and CWE hierarchical relationships.\n"

    per_sample_tokens = []
    per_hierarchy_tokens = []

    for i, s in enumerate(retrieved_samples):

        hierarchy = query_cwe_hierarchy(s["cwe_id"])
        s["hierarchy_text"] = build_hierarchy_text(hierarchy)

        if len(hierarchy) >= 2:
            s["patch"] = f"{hierarchy[-2]}->{hierarchy[-1]}"
        elif len(hierarchy) == 1:
            s["patch"] = hierarchy[0]
        else:
            s["patch"] = "Unknown"

        # ==== 样本主体部分 ====
        sample_text = (
            f"Sample {i + 1}:\n"
            f"- Code:\n  {s['func_before']}\n"
            f"- Description:\n  {s['description']}\n"
            f"- CWE-ID: {s['cwe_id']}\n"
            f"- Patch: {s.get('patch', 'Unknown')}\n"
        )
        prompt += sample_text
        per_sample_tokens.append(len(tokenizer.encode(sample_text)))

        # ==== 层级链路部分（单独统计算token） ====
        hierarchy_text = f"- CWE Hierarchy:\n{s.get('hierarchy_text', '(No hierarchy found)')}\n\n"
        prompt += hierarchy_text
        per_hierarchy_tokens.append(len(tokenizer.encode(hierarchy_text)))

    # ==== Step 2~5 ====
    prompt += (
        f"Step 2: Analyze the aforementioned several similar vulnerability samples.\n"
        f"For each sample, carefully consider how its code snippet and description map to its corresponding CWE type.\n"
        f"Identify which aspects of the code and description most clearly reflect the characteristics of the CWE.\n\n"
        f"Step 3: Analyze the hierarchical relationships corresponding to the CWE types of these samples.\n"
        f"Analyze the CWE hierarchy for each retrieved sample. For each sample's CWE, review its parent categories and hierarchical links, and reason about the conditions that match this CWE based on its official description, extended description, and common consequences. Specifically, for each CWE, consider:\n"
        f"- Parent categories\n"
        f"- Official description\n"
        f"- Extended description\n"
        f"Use this hierarchy-aware analysis to judge whether the target vulnerability's code and description fit a narrow, specific CWE or a broader parent CWE.\n\n"
        f"Step 4: Infer the CWE type of the target vulnerability.\n"
        f"Target vulnerability:\n"
        f"- Code: {query_code}\n"
        f"- Description: {query_desc}\n"
        f"Compare the target vulnerability with the previous similar samples, focusing on semantic and structural similarity of code and description.\n"
        f"Combine this with the hierarchical analysis to determine the most likely CWE type of the target vulnerability.\n"
        f"based on the reasoning in Step 2 and 3.\n\n"
        f"Step 5: Output only a single specific CWE ID (e.g., CWE-xxx).\n"
        f"Do not output any reasoning, explanations, or additional text; only the final label should be returned.\n\n"
    )


    return prompt, per_sample_tokens, per_hierarchy_tokens

# ================== 统计函数：返回 token 数 ==================
def count_tokens(system_content: str, user_content: str, tokenizer):
    sys_tokens  = len(tokenizer.encode(system_content))
    user_tokens = len(tokenizer.encode(user_content))
    return sys_tokens, user_tokens, sys_tokens + user_tokens

# ================== 运行入口 ==================
def main():
    INPUT_FILE = "output_dataset/Test_with_ast.csv"
    OUTPUT_DETAIL_FILE = "token_usage_stats.csv"
    OUTPUT_SUMMARY_FILE = "token_usage_summary.csv"

    df = pd.read_csv(INPUT_FILE)

    tokenizer = transformers.AutoTokenizer.from_pretrained(
        CHAT_TOKENIZER_DIR,
        local_files_only=True,
        trust_remote_code=False
    )

    rows = []

    for idx, row in df.iterrows():

        samples = rag_search(row["func_before"], row["description"], row["ast"])

        full_prompt, per_sample_tokens, per_hierarchy_tokens = \
            build_cwe_rag_cot_prompt(row["func_before"], row["description"], samples, tokenizer)

        sys_toks, user_toks, total_toks = count_tokens(SYSTEM_CONTENT, full_prompt, tokenizer)

        # ====== 样本 Token 结构统计 ======
        sample_total = int(np.sum(per_sample_tokens)) if per_sample_tokens else 0
        sample_avg = float(np.mean(per_sample_tokens)) if per_sample_tokens else 0.0
        sample_max = int(np.max(per_sample_tokens)) if per_sample_tokens else 0
        sample_share_user = (sample_total / user_toks) if user_toks > 0 else 0.0

        # ====== 层级链路 Token 统计 ======
        hierarchy_total = int(np.sum(per_hierarchy_tokens)) if per_hierarchy_tokens else 0
        hierarchy_avg = float(np.mean(per_hierarchy_tokens)) if per_hierarchy_tokens else 0.0
        hierarchy_max = int(np.max(per_hierarchy_tokens)) if per_hierarchy_tokens else 0
        hierarchy_share_user = (hierarchy_total / user_toks) if user_toks > 0 else 0.0

        row_out = {
            "row_id": idx,
            "system_tokens": sys_toks,
            "user_tokens": user_toks,
            "total_tokens": total_toks,

            # ====== Sample token analysis ======
            "sample_total_tokens": sample_total,
            "sample_avg_tokens": round(sample_avg, 2),
            "sample_max_tokens": sample_max,
            "sample_token_share_user": round(sample_share_user, 6),

            # ====== Hierarchy token analysis ======
            "hierarchy_total_tokens": hierarchy_total,
            "hierarchy_avg_tokens": round(hierarchy_avg, 2),
            "hierarchy_max_tokens": hierarchy_max,
            "hierarchy_token_share_user": round(hierarchy_share_user, 6),
        }

        # ====== 写入逐样本 token ======
        for i, t in enumerate(per_sample_tokens, start=1):
            row_out[f"Sample{i}_tokens"] = int(t)

        for i, t in enumerate(per_hierarchy_tokens, start=1):
            row_out[f"Hierarchy{i}_tokens"] = int(t)

        rows.append(row_out)

        if (idx + 1) % 100 == 0:
            print(f"[Progress] processed {idx + 1}/{len(df)} rows...")

    # ====== 保存统计明细 ======
    usage_df = pd.DataFrame(rows)
    usage_df.to_csv(OUTPUT_DETAIL_FILE, index=False)
    print(f"[Done] per-row token usage saved to {OUTPUT_DETAIL_FILE}")

    # ====== 生成 Summary ======
    def q(x, p):
        return float(x.quantile(p)) if len(x) else 0.0

    stats = {
        "N": len(usage_df),
        "total_mean": float(usage_df["total_tokens"].mean()),
        "total_median": float(usage_df["total_tokens"].median()),
        "total_min": int(usage_df["total_tokens"].min()),
        "total_max": int(usage_df["total_tokens"].max()),
        "total_std": float(usage_df["total_tokens"].std(ddof=1)),

        "p10": q(usage_df["total_tokens"], 0.10),
        "p25": q(usage_df["total_tokens"], 0.25),
        "p75": q(usage_df["total_tokens"], 0.75),
        "p90": q(usage_df["total_tokens"], 0.90),

        # Sample Token Summary
        "sample_mean": float(usage_df["sample_total_tokens"].mean()),
        "sample_min": int(usage_df["sample_total_tokens"].min()),
        "sample_max": int(usage_df["sample_total_tokens"].max()),

        # Hierarchy Token Summary
        "hierarchy_mean": float(usage_df["hierarchy_total_tokens"].mean()),
        "hierarchy_min": int(usage_df["hierarchy_total_tokens"].min()),
        "hierarchy_max": int(usage_df["hierarchy_total_tokens"].max()),

        "sample_share_mean": float(usage_df["sample_token_share_user"].mean()),
        "hierarchy_share_mean": float(usage_df["hierarchy_token_share_user"].mean())
    }

    pd.DataFrame([stats]).to_csv(OUTPUT_SUMMARY_FILE, index=False)
    print(f"[Done] Summary saved to {OUTPUT_SUMMARY_FILE}")

    print("\n========== 📊 Token Usage Summary ==========")
    for k, v in stats.items():
        print(f"{k}: {v:.2f}" if isinstance(v, float) else f"{k}: {v}")


if __name__ == "__main__":
    main()


