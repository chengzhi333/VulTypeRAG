"""CWE 图：节点知识文本 + 最长祖先链（CWE 是多父 DAG，不是树）。

图 JSON 结构（与 v1 产物一致）：
    {"cwe_version", "view_id", "edge_direction": "parent_to_child",
     "nodes": {"787": {"cweId", "nameEn", "description", ...}},
     "edges": [{"parent": 119, "child": 787}]}
"""

import json
from pathlib import Path

import config


class CWEGraph:
    def __init__(self, json_path):
        data = json.loads(Path(json_path).read_text(encoding="utf-8"))
        self.version = data.get("cwe_version", "")
        self.view_id = str(data.get("view_id") or "")
        self.nodes = data.get("nodes", {})

        parents = {}
        for edge in data.get("edges", []):
            parents.setdefault(str(edge["child"]), set()).add(str(edge["parent"]))
        self.parents = {k: tuple(sorted(v, key=int)) for k, v in parents.items()}

        # 类别通道语料：跳过视图节点（如 CWE-1000 Research Concepts）与无名称节点
        self.cwe_ids = [
            f"CWE-{cid}" for cid in sorted(self.nodes, key=int)
            if int(cid) > 0 and cid != self.view_id and self.nodes[cid].get("nameEn")
        ]

    @staticmethod
    def _node_id(cwe_id):
        """'CWE-787' / '787' -> '787'；非 CWE 标签（如 Remain Class）-> None。"""
        digits = "".join(char for char in str(cwe_id) if char.isdigit())
        return str(int(digits)) if digits else None

    def node(self, cwe_id):
        node_id = self._node_id(cwe_id)
        return self.nodes.get(node_id, {}) if node_id else {}

    def node_text(self, cwe_id):
        """候选节点的官方知识文本。"""
        node = self.node(cwe_id)
        lines = [str(cwe_id)]
        for field, label in (("nameEn", "Name"),
                             ("description", "Description"),
                             ("extendedDescription", "Extended Description"),
                             ("commonConsequences", "Common Consequences")):
            value = node.get(field)
            if value and value != "[]":
                lines.append(f"- {label}: {value}")
        return "\n".join(lines)

    def bm25_text(self, cwe_id):
        """论文 3.3.2：类别通道文档只含 CWE 名称与描述（不含扩展描述/后果）。"""
        node = self.node(cwe_id)
        return " ".join(str(node.get(field)) for field in config.BM25_FIELDS if node.get(field))

    def path(self, cwe_id):
        """最长祖先链，方向 父 -> 子，末位是自身；未知节点返回自身；非 CWE 标签返回 []。"""
        start = self._node_id(cwe_id)
        if start is None:
            return []
        best = [start]

        def walk(node, chain, seen):
            nonlocal best
            if len(chain) > len(best):
                best = list(chain)
            for parent in self.parents.get(node, ()):
                if parent not in seen:
                    walk(parent, chain + [parent], seen | {parent})

        if start in self.nodes:
            walk(start, [start], {start})
        return [f"CWE-{cid}" for cid in reversed(best)]

    def hierarchy_text(self, cwe_ids):
        return "\n".join(f"{cwe_id}: " + " -> ".join(self.path(cwe_id)) for cwe_id in cwe_ids)

    def patch_text(self, cwe_id):
        """层级链末两级，与 case.docx 的 - Patch: 119->787 写法一致（去掉 CWE- 前缀）。"""
        path = [cid.replace("CWE-", "") for cid in self.path(cwe_id)]
        if len(path) >= 2:
            return f"{path[-2]}->{path[-1]}"
        return path[-1] if path else ""

    def collect_knowledge(self, cwe_ids):
        """候选集合的知识图谱上下文：节点定义 + 祖先链；共享祖先的说明只保留一份。"""
        candidate_ids = list(dict.fromkeys(cwe_ids))
        ancestor_ids = []
        for cwe_id in candidate_ids:
            for ancestor in self.path(cwe_id):
                if ancestor not in candidate_ids and ancestor not in ancestor_ids:
                    ancestor_ids.append(ancestor)
        paths = "\n".join(f"{cid}: " + " -> ".join(self.path(cid)) for cid in candidate_ids)
        ancestor_text = "\n\n".join(self.node_text(cid) for cid in ancestor_ids)
        return {
            "hierarchy_paths": [{"cwe_id": cid, "path": self.path(cid)} for cid in candidate_ids],
            "ancestor_cwe_ids": ancestor_ids,
            "candidate_knowledge": "\n\n".join(self.node_text(cid) for cid in candidate_ids),
            "hierarchy_knowledge": (
                "Direction: broader parent -> more specific child.\n" + paths
                + "\n\nAncestor node definitions (candidate definitions are provided above):\n"
                + (ancestor_text or "No additional ancestor nodes.")),
        }