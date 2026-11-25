# VulTypeRAG

Official implementation of the paper **“Improving Software Vulnerability Type Identification via Dual-Channel Retrieval and CWE Knowledge Graph”**.

VulTypeRAG assigns a CWE type to a vulnerable function together with its natural-language
vulnerability description. It combines **instance-level retrieval**, a **category channel driven by
an LLM-generated behavior summary**, a **CWE knowledge graph**, and **four-step Chain-of-Thought
prompting**.

![Framework](figs/famework.png)

> A complete workflow example (the CoT prompt and the LLM reasoning output for one sample) is
> available in [`case.docx`](case.docx), as referenced in the paper.

> `code/` is a self-contained, runnable implementation of the complete pipeline:
> dataset construction → instance knowledge base → behavior summary → dual-channel retrieval →
> CWE knowledge graph → 4-step CoT → post-processing → evaluation.

---

## 1. Method at a glance

| Stage                | What happens                                                 |
| -------------------- | ------------------------------------------------------------ |
| **Knowledge base**   | Training instances (code + description + CWE label); official CWE texts (name + description); CWE knowledge graph built from View-1000 (`ChildOf` edges). |
| **Instance channel** | CodeBERT encodes code, text2vec encodes descriptions (last-layer mean pooling, L2). Code candidates are recalled `2k`-wise and re-ranked by `CodeSim = λ·SynSim + (1−λ)·LexSim` (AST-sequence Levenshtein + token Jaccard); description candidates are merged and the final score is `Sim = φ·CodeSim + (1−φ)·DescSim`. |
| **Category channel** | An LLM summarizes the vulnerability behavior (key operations, affected objects, triggering conditions, weakness mechanism, ≤50 English words). The summary is the BM25 query over CWE name+description; ranking is restricted to the training label space. |
| **Fusion + KG**      | Candidates from both channels are de-duplicated (instance candidates first, then unseen category candidates in BM25 order) and annotated with sources; candidate definitions, ancestor paths and deduplicated ancestor descriptions are pulled from the knowledge graph. |
| **Classification**   | A four-step CoT prompt (context → semantic mapping of examples → CWE hierarchy analysis → target inference) asks the LLM for the final CWE ID. |
| **Post-processing**  | Predictions are normalized; anything outside the training label space becomes `Remain Class`. |
| **Evaluation**       | Accuracy, weighted F1, macro MCC, plus per-channel Recall@k and MRR as retrieval diagnostics. |

---

## 2. Repository structure

```
.
├── README.md
├── figs/famework.png
└── code/                      # minimal runnable implementation
    ├── config.py              # paths, models, hyper-parameters
    ├── build_dataset.py       # raw .xlsx -> output_dataset/*_with_ast.csv
    ├── prepare_cwe.py         # CWE View-1000 (.xml/.csv) -> knowledge graph JSON
    ├── prepare_data.py        # train/test preparation + label space
    ├── build_index.py         # instance embeddings -> FAISS indexes
    ├── llm_client.py          # OpenAI-compatible chat client
    ├── llm_summary.py         # LLM behavior summary (cached by content hash)
    ├── retriever.py           # dual-channel retrieval + KG context
    ├── classify.py            # CWE-KG + 4-step CoT classification
    ├── postprocess.py         # label-space normalization / Remain Class
    ├── evaluate.py            # ACC / weighted F1 / macro MCC + Recall@k / MRR
    ├── run_pipeline.py        # one-command pipeline
    ├── cwe_graph.py  bm25.py  embedder.py
    └── assets/cwe_graph.json  # CWE 4.18 graph (945 nodes, 1080 edges)
```

---

## 3. Dataset

The dataset is too large for GitHub and is hosted on Google Drive:

**[Google Drive — dataset](https://drive.google.com/drive/folders/1XHCv3CUSde5AO98ttmdvNQi_gexber42)**

After downloading, the raw files should look like this (`datasets1/` and `dataset1/` are both accepted):

```
datasets1/
├── 原始.xlsx      # vulnerable functions: cve_id / cwe_ids / func_before / description
├── 1000.xml       # official CWE View-1000 data (knowledge graph + hierarchy)
└── 1000.csv       # CSV export of View-1000 (fallback when XML is unavailable)
```

Build the splits (cleaning, `Remain Class` grouping for types with <20 samples, stratified 8:1:1,
AST linearization with tree-sitter):

```bash
python code/build_dataset.py
```

Outputs in `output_dataset/`:

```
Samples.csv / CWE_Proportion.csv
Train.csv / Val.csv / Test.csv                              # without AST
Train_with_ast.csv / Val_with_ast.csv / Test_with_ast.csv    # with AST
```

`Train_with_ast.csv` is used as the instance knowledge base, `Test_with_ast.csv` as the test set.

---

## 4. Quick start

```bash
git clone https://github.com/chengzhi333/VulTypeRAG.git
cd VulTypeRAG
pip install -r code/requirements.txt        # torch, transformers, faiss-cpu, pandas, ...

# 1) build the dataset (after downloading it into datasets1/)
python code/build_dataset.py
python code/prepare_cwe.py                 # optional: rebuild the CWE graph from 1000.xml

# 2) configure the LLM (any OpenAI-compatible endpoint)
cp code/llm_config.example.json code/llm_config.json   # fill base_url / api_key / model
#    or export LITELLM_BASE_URL / LITELLM_API_KEY / LITELLM_MODEL

# 3) run the full pipeline
python code/run_pipeline.py
```

The pipeline writes to `code/data/`:

```
train.csv / val.csv / test.csv      label_space.json
index/                              behavior_summaries.csv
context.jsonl                       results/{retrieval.csv, predictions.csv, final.csv, eval.json}
```

LLM calls are cached (`behavior_summaries.csv`, `predictions.csv`), so interrupted runs resume
without paying for the same sample twice.

### Reproducing the paper's ablations

The released pipeline is the full model; the corresponding knobs live in `code/config.py`:

| Paper factor                             | Knob                                                         |
| ---------------------------------------- | ------------------------------------------------------------ |
| Instance-channel weights (RQ2)           | `CODE_FUSE_W` / `DESC_FUSE_W` (φ), `SYNTAX_W` / `LEXICAL_W` (λ) |
| Retrieval depth (RQ3)                    | `TOPK`, `CODE_RECALL`, `CWE_TOPK`                            |
| Category channel / hierarchy / CoT (RQ4) | query source in `retriever.category_channel`, `cwe_graph.collect_knowledge`, `classify.build_prompt` |
