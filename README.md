## VulTypeRAG: Improving Software Vulnerability Type Identification via Retrieval-Augmented Generation and CWE Knowledge Graph

This is the source code to the paper "VulTypeRAG: Improving Software Vulnerability Type Identification via Retrieval-Augmented Generation and CWE Knowledge Graph". Please refer to the paper for the experimental details.

## Approach
![image](https://github.com/chengzhi333/VulTypeRAG/blob/main/figs/famework.png)

## About dataset 

The dataset files are large in size, so we have stored them in Google Drive: [Google Drive Link](https://drive.google.com/drive/folders/1XHCv3CUSde5AO98ttmdvNQi_gexber42).


## About the experimental results in the paper:

1.The results for `RQ1`, `RQ2`, `RQ3`, `RQ4`, and `RQ5` are stored in their corresponding folders.  
2.The experimental results for the discussion section are stored in the `discussion1` and `discussion2` folders.  

## For reproducing the experiments:

1.Download the `dataset` and configure the `file paths`.  
2.Run `RQ2-RQ5.py` to call the LLM and perform the SVTI task.  
3.Run `evaluation.py` to conduct the metric evaluation.  

