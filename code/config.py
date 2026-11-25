"""集中配置：路径、编码模型、检索超参、LLM 与生成物。"""

import sys
from pathlib import Path

for stream in (sys.stdout, sys.stderr):          # Windows 控制台统一 UTF-8
    if hasattr(stream, "reconfigure"):
        stream.reconfigure(encoding="utf-8")

CODE_DIR = Path(__file__).resolve().parent
ROOT_DIR = CODE_DIR.parent
DATA_DIR = CODE_DIR / "data"
ASSET_DIR = CODE_DIR / "assets"

# ---------- 原始数据集（不打进仓库，按 README 下载）----------
# 下载后解压得到 datasets1/：原始.xlsx（漏洞样本）、1000.xml / 1000.csv（CWE View-1000）
RAW_DIRS = (ROOT_DIR / "datasets1", ROOT_DIR / "dataset1")      # 两种历史目录名都兼容
RAW_XLSX = RAW_DIRS[0] / "原始.xlsx"                              # 原始漏洞数据（cve_id/cwe_ids/func_before/description）
CWE_XML = RAW_DIRS[0] / "1000.xml"                                # 官方 CWE View-1000
CWE_CSV = RAW_DIRS[0] / "1000.csv"                                # View-1000 的 CSV 导出（XML 缺失时的降级来源）
AST_LANGUAGE = "cpp"                                              # tree-sitter 语法（原始数据是 C/C++ 函数）

# ---------- 数据集产物（build_dataset.py 生成，供测试集与实例知识库使用）----------
OUTPUT_DATASET_DIR = ROOT_DIR / "output_dataset"
SAMPLES_CSV = OUTPUT_DATASET_DIR / "Samples.csv"
PROPORTION_CSV = OUTPUT_DATASET_DIR / "CWE_Proportion.csv"
TRAIN_WITH_AST = OUTPUT_DATASET_DIR / "Train_with_ast.csv"
VAL_WITH_AST = OUTPUT_DATASET_DIR / "Val_with_ast.csv"
TEST_WITH_AST = OUTPUT_DATASET_DIR / "Test_with_ast.csv"
# 论文 4.2 中已在 CWE 官网标记为 PROHIBITED/废弃、需要剔除的类型
REMOVED_CWES = (
    "CWE-399", "CWE-189", "CWE-254", "CWE-19", "CWE-388", "CWE-17", "CWE-1187",
    "CWE-310", "CWE-264", "CWE-384", "CWE-273", "CWE-276", "CWE-434", "CWE-611",
    "CWE-552", "CWE-320", "CWE-361",
)

# ---------- 输入素材 ----------
SOURCE_CSV = TRAIN_WITH_AST                          # 单文件模式/快速验证时的默认输入
CWE_JSON = ASSET_DIR / "cwe_graph.json"              # 由官方 CWE 4.18 XML 生成

# ---------- 生成物 ----------
TRAIN_CSV = DATA_DIR / "train.csv"
VAL_CSV = DATA_DIR / "val.csv"
TEST_CSV = DATA_DIR / "test.csv"
LABEL_SPACE_JSON = DATA_DIR / "label_space.json"
INDEX_DIR = DATA_DIR / "index"
SUMMARY_CSV = DATA_DIR / "behavior_summaries.csv"
CONTEXT_JSONL = DATA_DIR / "context.jsonl"
RESULT_DIR = DATA_DIR / "results"
RESULT_CSV = RESULT_DIR / "retrieval.csv"
PREDICTION_CSV = RESULT_DIR / "predictions.csv"
FINAL_CSV = RESULT_DIR / "final.csv"
EVAL_JSON = RESULT_DIR / "eval.json"

CSV_COLUMNS = ("cve_id", "func_before", "ast", "description", "cwe_id")
REMAIN_CLASS = "Remain Class"

# ---------- 编码器（本地权重，不是 LLM）----------
CODE_MODEL = "microsoft/codebert-base"                    # 代码 + AST，768 维
DESC_MODEL = "shibing624/text2vec-base-multilingual"      # 描述，384 维
MAX_LENGTH = 512
BATCH_SIZE = 16

# ---------- 实例通道超参（论文式 (6)(7)）----------
TOPK = 3            # 最终候选数（论文 RQ3 最优 k=3）
CODE_RECALL = 6     # 代码通道粗召回数（2 * TOPK）
SYNTAX_W = 0.4      # λ：AST 序列 Levenshtein 结构相似度权重
LEXICAL_W = 0.6     # 1-λ：词面 Jaccard 相似度权重
CODE_FUSE_W = 0.6   # φ：代码相似度权重
DESC_FUSE_W = 0.4   # 1-φ：描述相似度权重
AST_MAX_TOKENS = 300  # Levenshtein 计算时的 AST 序列截断长度

# ---------- 类别通道（BM25）超参 ----------
CWE_TOPK = 3
BM25_K1 = 1.5
BM25_B = 0.75
BM25_FIELDS = ("nameEn", "description")

# ---------- LLM（行为摘要 + 4 步 CoT）----------
LLM_CONFIG_PATH = CODE_DIR / "llm_config.json"     # 可被环境变量覆盖
LLM_ENV = {"base_url": "LITELLM_BASE_URL", "api_key": "LITELLM_API_KEY", "model": "LITELLM_MODEL"}
SUMMARY_WORD_LIMIT = 50
SUMMARY_MAX_TOKENS = 192
COT_MAX_TOKENS = 512
SUMMARY_WORKERS = 4
COT_WORKERS = 4

# ---------- 数据处理（论文 4.2）----------
TRAIN_RATIO, VAL_RATIO, TEST_RATIO = 0.8, 0.1, 0.1
MIN_CLASS_SAMPLES = 20      # 样本数少于该值的 CWE 类型归入 Remain Class
SEED = 42