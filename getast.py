# coding:utf-8
import pandas as pd
import re
from tree_sitter import Language, Parser
from tqdm import tqdm

# ================== 配置 ==================
# INPUT_CSV = "output_dataset/Test.csv"
INPUT_CSV = "output_dataset/Train.csv"
# OUTPUT_CSV = "output_dataset/Test_with_ast.csv"
OUTPUT_CSV = "output_dataset/Train_with_ast.csv"
LANG_SO = "build/my-languages.so"  # tree-sitter 语言库路径
LANG_NAME = "cpp"                  # 语言类型

# ================== 加载 Tree-sitter 解析器 ==================
CPP_LANGUAGE = Language(LANG_SO, LANG_NAME)
cpp_parser = Parser()
cpp_parser.set_language(CPP_LANGUAGE)

# ================== 读取数据 ==================
df = pd.read_csv(INPUT_CSV)

code_list = df["func_before"].astype(str).tolist()
ast_list = []

# ================== 生成 AST ==================
print(f"开始解析 {len(code_list)} 个函数为 AST ...")

for code in tqdm(code_list):
    tree = cpp_parser.parse(bytes(code, "utf8"))
    root = tree.root_node
    sexp = root.sexp()
    # 清洗掉多余符号，使结果更简洁
    cleaned_sexp = re.sub(r'[:\(\)]', '', sexp)
    ast_list.append(cleaned_sexp)

# ================== 合并并保存结果 ==================
df["ast"] = ast_list
df.to_csv(OUTPUT_CSV, index=False, encoding="utf-8")

print(f"✅ AST 已添加为新列并保存至：{OUTPUT_CSV}")
