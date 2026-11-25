"""一键跑完整条链路。

数据集构建 -> 数据处理 -> 建索引 -> LLM 行为摘要 -> 双通道检索(+CWE 知识图谱上下文)
           -> 4 步 CoT 分类 -> 后处理 -> 评估

用法：
    # 0) 先按 README 下载原始数据到 datasets1/，然后
    python code/run_pipeline.py --build-dataset
    # 数据集已存在时直接跑
    python code/run_pipeline.py
    # 小规模验证（单文件模式：自动清洗并切分）
    python code/run_pipeline.py --input output_dataset/Train_with_ast.csv --limit 200 --limit-test 20
"""

import argparse
import subprocess
import sys

import config


def run(script, *arguments):
    command = [sys.executable, "-u", str(config.CODE_DIR / script), *map(str, arguments)]
    print("→ " + " ".join(command[2:]))
    result = subprocess.run(command, cwd=str(config.ROOT_DIR))
    if result.returncode != 0:
        raise SystemExit(f"{script} 失败（退出码 {result.returncode}）")


def main(argv=None):
    parser = argparse.ArgumentParser(description="VulTypeRAG 最小可运行全流程")
    parser.add_argument("--build-dataset", action="store_true",
                        help="先从 datasets1/原始.xlsx 生成 output_dataset/*_with_ast.csv")
    parser.add_argument("--raw", default=None, help="原始漏洞数据 .xlsx（默认自动查找 datasets1/原始.xlsx）")
    parser.add_argument("--xml", default="", help="CWE XML；给定时重建 CWE 图")
    parser.add_argument("--cwe-json", default=str(config.CWE_JSON))
    parser.add_argument("--input", default="", help="单文件模式：从该 CSV 清洗+切分（默认用已切分数据集）")
    parser.add_argument("--test-ratio", type=float, default=config.TEST_RATIO)
    parser.add_argument("--val-ratio", type=float, default=config.VAL_RATIO)
    parser.add_argument("--min-class-samples", type=int, default=config.MIN_CLASS_SAMPLES)
    parser.add_argument("--limit", type=int, default=0, help="单文件模式：清洗后只取前 N 行")
    parser.add_argument("--limit-train", type=int, default=0)
    parser.add_argument("--limit-test", type=int, default=0)
    parser.add_argument("--workers", type=int, default=0, help="LLM 并发（0=用 config 默认）")
    parser.add_argument("--skip-prepare", action="store_true")
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--skip-summary", action="store_true")
    parser.add_argument("--skip-classify", action="store_true")
    args = parser.parse_args(argv)

    if args.build_dataset:
        run("build_dataset.py", *(["--raw", args.raw] if args.raw else []),
            "--min-class-samples", args.min_class_samples,
            "--val-ratio", args.val_ratio, "--test-ratio", args.test_ratio)
    if args.xml:
        run("prepare_cwe.py", "--xml", args.xml)
        args.cwe_json = str(config.DATA_DIR / "cwe_graph.json")
    if not args.skip_prepare:
        if args.input:
            run("prepare_data.py", "--input", args.input, "--limit", args.limit,
                "--min-class-samples", args.min_class_samples,
                "--val-ratio", args.val_ratio, "--test-ratio", args.test_ratio)
        else:
            run("prepare_data.py")
    if not args.skip_build:
        run("build_index.py", "--limit", args.limit_train)

    workers = (["--workers", args.workers] if args.workers else [])
    if not args.skip_summary:
        run("llm_summary.py", "--input", config.TEST_CSV, "--limit", args.limit_test, *workers)
    run("retriever.py", "--cwe-json", args.cwe_json, "--limit", args.limit_test)
    if not args.skip_classify:
        run("classify.py", "--limit", args.limit_test, *workers)
    run("postprocess.py")
    run("evaluate.py")

    print(f"\n完成：{config.FINAL_CSV}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())