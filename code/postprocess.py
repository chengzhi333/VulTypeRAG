"""第 6 步：后处理（对应 v1 的 houchuli_v1.py）。

作用：把 LLM 的原始输出收敛到训练集标签空间——
  1. 规范化 CWE 写法（cwe-787 / CWE 787 / CWE-787 -> CWE-787）
  2. 解析不出编号、或编号不在训练集标签空间内的预测，统一记为 Remain Class

与 v1 的区别：v1 的后处理读取金标 cweid 判断哪些行是 Remain Class（评测时构成信息泄漏），
这里只看预测本身，不接触金标。

用法：
    python code/postprocess.py
"""

import argparse
import json
from pathlib import Path

import pandas as pd

import config

CWE_FULL = __import__("re").compile(r"(?:CWE[-\s:]*)?(\d+)")


def canonical_label(value):
    match = CWE_FULL.fullmatch(str(value).strip())
    return f"CWE-{int(match[1])}" if match and int(match[1]) > 0 else None


def run(prediction_csv, label_space_path, output_csv):
    frame = pd.read_csv(prediction_csv, dtype=str, keep_default_na=False, encoding="utf-8-sig")
    space = json.loads(Path(label_space_path).read_text(encoding="utf-8"))["cwe_ids"]
    allowed = set(space)
    finals, mapped = [], 0
    for predicted in frame["predicted"]:
        label = canonical_label(predicted)
        if label in allowed:
            finals.append(label)
        else:
            finals.append(config.REMAIN_CLASS)
            mapped += 1
    frame["final"] = finals
    Path(output_csv).parent.mkdir(parents=True, exist_ok=True)
    frame.to_csv(output_csv, index=False, encoding="utf-8-sig")
    print(f"后处理：{len(frame)} 行，标签空间 {len(allowed)} 个 CWE，"
          f"{mapped} 行归入 {config.REMAIN_CLASS}")
    print(f"最终结果 -> {output_csv}")
    return mapped


def main(argv=None):
    parser = argparse.ArgumentParser(description="后处理：标签空间收敛 + Remain Class")
    parser.add_argument("--input", default=str(config.PREDICTION_CSV))
    parser.add_argument("--label-space", default=str(config.LABEL_SPACE_JSON))
    parser.add_argument("--output", default=str(config.FINAL_CSV))
    args = parser.parse_args(argv)
    run(args.input, args.label_space, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())