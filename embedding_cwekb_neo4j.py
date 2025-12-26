# coding:utf-8
import json
import numpy as np
import torch
from transformers import AutoTokenizer, AutoModel
from py2neo import Graph
import faiss
from tqdm import tqdm
import os

# ================== 全局配置 ===================
DEVICE = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
MAX_LENGTH = 256
POOLING = 'first_last_avg'

# ================== 模型加载 ===================
print("[INFO] 正在加载 Text2Vec 模型...")
desc_model_name = "shibing624/text2vec-base-multilingual"
desc_tokenizer = AutoTokenizer.from_pretrained(desc_model_name)
desc_model = AutoModel.from_pretrained(desc_model_name).to(DEVICE)
desc_model.eval()

# ================== 向量化函数 ===================
def embed_desc(text):
    """使用 Text2Vec 对 CWE 描述进行向量化"""
    if not isinstance(text, str) or not text.strip():
        text = "empty"
    inputs = desc_tokenizer(text, return_tensors="pt", truncation=True, padding=True, max_length=MAX_LENGTH)
    inputs = {k: v.to(DEVICE) for k, v in inputs.items()}
    with torch.no_grad():
        outputs = desc_model(**inputs, output_hidden_states=True, return_dict=True)
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


# ================== 主函数 ===================
def main():
    print("[INFO] 正在连接 Neo4j 数据库...")
    graph = Graph("bolt://localhost:7687", auth=("neo4j", "czj10261026"))

    print("[INFO] 开始读取 CWE 节点...")
    query = """
    MATCH (n:CWE)
    RETURN n.cweId AS id, n.description AS d1, n.extendedDescription AS d2
    ORDER BY n.cweId
    """
    results = graph.run(query).data()
    print(f"[INFO] 共获取到 {len(results)} 个 CWE 节点")

    cwe_ids = []
    cwe_texts = []

    for item in results:
        cid = item.get("id")
        d1 = (item.get("d1") or "").strip()
        d2 = (item.get("d2") or "").strip()
        text = f"{d1}\n{d2}".strip() or d1 or d2
        if cid and text:
            cwe_ids.append(int(cid))
            cwe_texts.append(text)

    print(f"[INFO] 可用于向量化的 CWE 节点数量: {len(cwe_ids)}")

    # 向量化
    desc_vec_list = []
    print("[INFO] 开始向量化 CWE 描述文本...")
    for text in tqdm(cwe_texts, desc="Embedding CWE Texts"):
        desc_vec = embed_desc(text)
        desc_vec_list.append(desc_vec)

    desc_vec_np = np.array(desc_vec_list, dtype='float32')

    # 构建 FAISS 索引
    print("[INFO] 开始建立 FAISS 索引...")
    index_desc = faiss.IndexFlatL2(desc_vec_np.shape[1])
    index_desc.add(desc_vec_np)

    # 创建保存目录
    os.makedirs("faiss", exist_ok=True)

    # 保存索引
    faiss.write_index(index_desc, "faiss/faiss_index_cwe_desc.index")

    # 保存 id 映射
    id_map = {str(i): int(cwe_ids[i]) for i in range(len(cwe_ids))}
    with open("faiss/cwe_id_map.json", "w", encoding="utf-8") as f:
        json.dump(id_map, f, indent=2, ensure_ascii=False)

    print("✅ 全部完成！CWE 索引已保存至 faiss/faiss_index_cwe_desc.index")
    print("✅ ID 映射文件已保存为 faiss/cwe_id_map.json")


if __name__ == "__main__":
    main()
