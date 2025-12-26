import json
import psycopg2
from py2neo import Graph
from tqdm import tqdm

# ================== 全局配置 ==================
BATCH_SIZE = 1000
WIPE_ALL = True  # 是否清空 Neo4j

# ================== 从 PostgreSQL 读取数据 ==================
def fetch_from_postgres( ):
    """从 PostgreSQL 读取 CWE 节点与层级路径信息"""
    print("[INFO] 正在连接 PostgreSQL 数据库...")
    conn = psycopg2.connect(
        host="localhost",
        port=5432,
        dbname="rag-type",
        user="postgres",
        password="123456",
    )
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT cweId, nameEn, status, description, extendedDescription, commonConsequences, patch
            FROM cwe_node
            ORDER BY cweId
            """
        )
        rows = cur.fetchall()
    finally:
        conn.close()

    nodes = []
    edges_set = set()

    def _normalize_paths(patch_val):
        """解析 patch 字段为路径列表"""
        if patch_val is None:
            return []
        if isinstance(patch_val, list):
            return [str(x) for x in patch_val if x is not None]
        if isinstance(patch_val, (int,)):
            return [str(patch_val)]
        if isinstance(patch_val, str):
            s = patch_val.strip()
            if not s:
                return []
            try:
                parsed = json.loads(s)
                if isinstance(parsed, list):
                    return [str(x) for x in parsed if x is not None]
                else:
                    return [str(parsed)]
            except Exception:
                # 例如 "693->311->319"
                return [s]
        return []

    print(f"[INFO] 共读取到 {len(rows)} 条 CWE 节点记录")
    for (cwe_id, name_en, status, desc, ext_desc, common_cons, patch) in rows:
        node = {
            "cweId": int(cwe_id),
            "nameEn": name_en or "",
            "description": desc or "",
            "extendedDescription": ext_desc or "",
            "commonConsequences": common_cons or "[]",
        }
        nodes.append(node)

        paths = _normalize_paths(patch)
        for p in paths:
            parts = [s.strip() for s in p.split("->") if s.strip()]
            for i in range(len(parts) - 1):
                try:
                    parent = int(parts[i])
                    child = int(parts[i + 1])
                    edges_set.add((parent, child, 1000))
                except Exception:
                    continue

    edges = list(edges_set)
    print(f"[INFO] 解析完成：节点数={len(nodes)}, 关系数={len(edges)}")
    return nodes, edges

# ================== 写入 Neo4j ==================
def load_with_py2neo(graph, nodes, edges):
    """使用 Py2Neo 将 CWE 节点与关系批量写入 Neo4j"""
    print("[INFO] 正在写入 Neo4j 图数据库...")
    graph.run("CREATE CONSTRAINT cwe_id_unique IF NOT EXISTS FOR (n:CWE) REQUIRE n.cweId IS UNIQUE")

    node_query = (
        """
        UNWIND $rows AS row
        MERGE (n:CWE {cweId: row.cweId})
        SET n.nameEn = row.nameEn,
            n.description = row.description,
            n.extendedDescription = row.extendedDescription,
            n.commonConsequences = row.commonConsequences,
            n.name = toString(row.cweId)
        """
    )

    rel_query = """
            UNWIND $rows AS row
            MERGE (p:CWE {cweId: row.parent})
              ON CREATE SET p.type = coalesce(p.type, 'Unknown')
            MERGE (c:CWE {cweId: row.child})
              ON CREATE SET c.type = coalesce(c.type, 'Unknown')
            MERGE (p)-[:ChildOf {viewId: row.viewId}]->(c)
        """

    #写入节点
    print(f"[INFO] 正在写入 {len(nodes)} 个节点...")
    for i in tqdm(range(0, len(nodes), BATCH_SIZE), desc="写入节点批次"):
        graph.run(node_query, rows=nodes[i:i + BATCH_SIZE])

    # 写入关系
    rel_rows = [{"parent": p, "child": c, "viewId": v} for p, c, v in edges]
    print(f"[INFO] 正在写入 {len(rel_rows)} 条关系...")
    for i in tqdm(range(0, len(rel_rows), BATCH_SIZE), desc="写入关系批次"):
        graph.run(rel_query, rows=rel_rows[i:i + BATCH_SIZE])

    print("✅ Neo4j 数据导入完成！")

# ================== 主程序入口 ==================
def main():
    print("[INFO] ===== CWE 知识库导入程序 =====")
    print(f"[INFO] PostgreSQL")
    print(f"[INFO] Neo4j")
    print("[INFO] ==================================")

    nodes, edges = fetch_from_postgres()

    graph = Graph("bolt://localhost:7687", auth=("neo4j", "czj10261026"))
    if WIPE_ALL:
        print("[WARN] 清空 Neo4j 图数据库中所有节点和关系...")
        graph.run("MATCH (n) DETACH DELETE n")

    load_with_py2neo(graph, nodes, edges)
    print("✅ 全部导入完成！")


if __name__ == "__main__":
    main()


