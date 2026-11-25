"""第 0 步（可选）：CWE 官方 XML -> 图 JSON。

输出结构与 v1 产物一致，供 cwe_graph.py / retriever.py 直接读取：
    {"cwe_version", "view_id", "edge_direction": "parent_to_child",
     "nodes": {...}, "edges": [{"parent": 119, "child": 787}]}

与 v1 的 cwekb_v1.py 相比删掉了 SQLite 中转、24 列全字段和递归 CTE：
这里直接从 <Weaknesses> 取节点、从 Related_Weakness(Nature=ChildOf) 取父子边，
层级路径改为查询时在 DAG 上做 DFS（cwe_graph.CWEGraph.path）。

用法：
    python code/prepare_cwe.py --xml datasets1/1000.xml
"""

import argparse
import json
import xml.etree.ElementTree as ET
from pathlib import Path

import pandas as pd

import config

NS = {"cwe": "http://cwe.mitre.org/cwe-7"}


def _text(element):
    """取元素下全部文本（含内嵌 xhtml 子节点），折叠空白。

    v1 里只取 element.text，遇到 <Description><xhtml:div> 时会被截断。
    """
    if element is None:
        return ""
    return " ".join("".join(element.itertext()).split())


def _consequences(weakness):
    items = []
    for consequence in weakness.findall("cwe:Common_Consequences/cwe:Consequence", NS):
        entry = {}
        for child in consequence:
            tag = child.tag.split("}")[-1]
            text = _text(child)
            if not text:
                continue
            if tag in entry:
                previous = entry[tag]
                entry[tag] = (previous + [text]) if isinstance(previous, list) else [previous, text]
            else:
                entry[tag] = text
        if entry:
            items.append(entry)
    return json.dumps(items, ensure_ascii=False) if items else "[]"


def _weaknesses(root):
    """兼容两种官方 XML 形态：根下嵌套 <Weaknesses> 或直接是 <Weakness> 列表。"""
    found = root.findall("cwe:Weaknesses/cwe:Weakness", NS)
    return found or root.findall("cwe:Weakness", NS)


def build_graph(xml_path):
    root = ET.parse(xml_path).getroot()
    nodes, edges = {}, set()
    for weakness in _weaknesses(root):
        cwe_id = int(weakness.get("ID"))
        nodes[str(cwe_id)] = {
            "cweId": cwe_id,
            "nameEn": _text(weakness.find("cwe:Name", NS)),
            "description": _text(weakness.find("cwe:Description", NS)),
            "extendedDescription": _text(weakness.find("cwe:Extended_Description", NS)),
            "commonConsequences": _consequences(weakness),
        }
        for relation in weakness.findall("cwe:Related_Weaknesses/cwe:Related_Weakness", NS):
            parent = relation.get("CWE_ID")
            if relation.get("Nature") == "ChildOf" and parent and parent.isdigit():
                edges.add((int(parent), cwe_id))

    # 只被边引用、本体未定义的父节点补空节点，保证层级链不断
    for parent, child in edges:
        for node_id in (parent, child):
            nodes.setdefault(str(node_id), {"cweId": node_id})

    return {
        "cwe_version": root.get("Version", ""),
        "view_id": 1000,
        "edge_direction": "parent_to_child",
        "nodes": dict(sorted(nodes.items(), key=lambda item: int(item[0]))),
        "edges": [{"parent": parent, "child": child, "viewId": 1000}
                  for parent, child in sorted(edges)],
    }


def build_graph_from_csv(csv_path):
    """1000.csv（View-1000 导出）-> 仅节点的图 JSON（无父子边）。

    XML 缺失时的降级路径：类别通道与候选知识仍可用，但没有层级链。
    """
    frame = pd.read_csv(csv_path, dtype=str, keep_default_na=False, encoding="utf-8-sig")

    def pick(*keywords, exclude=()):
        for column in frame.columns:
            name = str(column).strip().lower()
            if any(word in name for word in keywords) and not any(word in name for word in exclude):
                return column
        return None

    id_col = pick("cwe", "id") or frame.columns[0]
    name_col = pick("name", "title", exclude=("file",))
    desc_col = pick("description", "desc", exclude=("extended",))
    extended_col = pick("extended")
    consequences_col = pick("consequence")
    nodes = {}
    for record in frame.to_dict("records"):
        digits = "".join(char for char in str(record.get(id_col, "")) if char.isdigit())
        if not digits:
            continue
        cwe_id = int(digits)
        nodes[str(cwe_id)] = {
            "cweId": cwe_id,
            "nameEn": str(record.get(name_col, "")).strip() if name_col else "",
            "description": str(record.get(desc_col, "")).strip() if desc_col else "",
            "extendedDescription": str(record.get(extended_col, "")).strip() if extended_col else "",
            "commonConsequences": str(record.get(consequences_col, "")).strip()
            if consequences_col else "[]",
        }
    if not nodes:
        raise ValueError(f"{csv_path} 里没有解析出 CWE 节点")
    return {"cwe_version": "", "view_id": 1000, "edge_direction": "parent_to_child",
            "nodes": dict(sorted(nodes.items(), key=lambda item: int(item[0]))), "edges": []}


def _resolve(path, candidates):
    if path:
        return Path(path)
    for candidate in candidates:
        if Path(candidate).is_file():
            return Path(candidate)
    return None


def main(argv=None):
    parser = argparse.ArgumentParser(description="CWE 知识库：XML/CSV -> 图 JSON")
    parser.add_argument("--xml", default="", help=f"官方 CWE XML（默认找 {config.CWE_XML}）")
    parser.add_argument("--csv", default="", help=f"View-1000 的 CSV（默认找 {config.CWE_CSV}，XML 缺失时降级使用）")
    parser.add_argument("--out", default=str(config.DATA_DIR / "cwe_graph.json"))
    args = parser.parse_args(argv)

    xml_path = Path(args.xml) if args.xml else None
    csv_path = Path(args.csv) if args.csv else None
    if xml_path is None and csv_path is None:      # 未显式指定时自动查找：XML 优先
        xml_path = _resolve(None, (config.CWE_XML, *[d / "1000.xml" for d in config.RAW_DIRS]))
        csv_path = _resolve(None, (config.CWE_CSV, *[d / "1000.csv" for d in config.RAW_DIRS]))
    if xml_path is not None:
        data = build_graph(xml_path)
        print(f"来源: {xml_path}")
    elif csv_path is not None:
        data = build_graph_from_csv(csv_path)
        print(f"来源: {csv_path}（仅节点，无层级边；要层级请提供 1000.xml）")
    else:
        raise FileNotFoundError(
            "找不到 CWE 数据：请把 1000.xml / 1000.csv 放到 datasets1/，"
            "或用 --xml / --csv 指定；仓库自带 code/assets/cwe_graph.json 可直接使用。")
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"CWE {data['cwe_version']}: 节点 {len(data['nodes'])} / 边 {len(data['edges'])} -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())