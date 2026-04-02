import logging
import math
from typing import Optional, Tuple, Dict, Any

from overrides import overrides

import torch
import torch.nn.functional as F
from transformers import XLNetConfig

from allennlp.data.tokenizers import PretrainedTransformerTokenizer
from allennlp.modules.scalar_mix import ScalarMix
from allennlp.modules.token_embedders.token_embedder import TokenEmbedder
from allennlp.nn.util import batched_index_select

logger = logging.getLogger(__name__)

# 自定义预训练Transformer嵌入器类
# 该类继承自TokenEmbedder，用于将输入token转换为嵌入表示
@TokenEmbedder.register("custom_pretrained_transformer")
class CustomPretrainedTransformerEmbedder(TokenEmbedder):
    """
    使用transformers库中的预训练模型作为TokenEmbedder。
    注册为名为"pretrained_transformer"的TokenEmbedder。

    参数:
    model_name : str
        要使用的transformers模型名称。应与相应的PretrainedTransformerIndexer相同。
    max_length : int, 可选 (默认 = None)
        如果为正数，则将输入token ID折叠成多个此长度的段，独立通过transformer模型，
        并连接最终表示。应与PretrainedTransformerIndexer的max_length选项设置相同。
    sub_module: str, 可选 (默认 = None)
        用作嵌入器的transformer子模块名称。一些transformer模型（如BERT）自然充当嵌入器。
        其他模型由编码器和解码器组成，此时我们只想使用编码器。
    train_parameters: bool, 可选 (默认 = True)
        如果为True，transformer权重在训练期间更新。如果为False，则不更新。
    eval_mode: bool, 可选 (默认 = False)
        如果为True，模型始终设置为评估模式（例如，禁用dropout和批归一化层统计更新）。
        如果为False，这些层仅在模型评估开发或测试数据时设置为评估模式。
    last_layer_only: bool, 可选 (默认 = True)
        当为True（默认）时，仅使用预训练transformer的最后一层进行嵌入。
        如果设置为False，则使用所有层的标量混合。
    gradient_checkpointing: bool, 可选 (默认 = None)
        启用或禁用梯度检查点。
    tokenizer_kwargs: Dict[str, Any], 可选 (默认 = None)
        用于AutoTokenizer.from_pretrained的额外参数字典。
    transformer_kwargs: Dict[str, Any], 可选 (默认 = None)
        用于AutoModel.from_pretrained的额外参数字典。
    """

    # 允许缺失的键
    authorized_missing_keys = [r"position_ids$"]

    def __init__(
        self,
        model_name: str,
        *,
        max_length: int = None,
        sub_module: str = None,
        train_parameters: bool = True,
        eval_mode: bool = False,
        last_layer_only: bool = True,
        type_vocab_size: int = 1,
        override_weights_file: Optional[str] = None,
        override_weights_strip_prefix: Optional[str] = None,
        gradient_checkpointing: Optional[bool] = None,
        tokenizer_kwargs: Optional[Dict[str, Any]] = None,
        transformer_kwargs: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__()
        from allennlp.common import cached_transformers

        # 获取预训练模型
        self.transformer_model = cached_transformers.get(
            model_name,
            True,
            override_weights_file=override_weights_file,
            override_weights_strip_prefix=override_weights_strip_prefix,
            **(transformer_kwargs or {}),
        )

        # 设置梯度检查点
        if gradient_checkpointing is not None:
            self.transformer_model.config.update({"gradient_checkpointing": gradient_checkpointing})

        self.config = self.transformer_model.config
        if sub_module:
            assert hasattr(self.transformer_model, sub_module)
            self.transformer_model = getattr(self.transformer_model, sub_module)
        self._max_length = max_length

        self.output_dim = self.config.hidden_size

        # 设置标量混合（用于多层的混合）
        self._scalar_mix: Optional[ScalarMix] = None
        if not last_layer_only:
            self._scalar_mix = ScalarMix(self.config.num_hidden_layers)
            self.config.output_hidden_states = True

        # 初始化tokenizer
        tokenizer = PretrainedTransformerTokenizer(
            model_name,
            tokenizer_kwargs=tokenizer_kwargs,
        )

        # 调整token嵌入矩阵大小
        try:
            if self.transformer_model.get_input_embeddings().num_embeddings != len(
                tokenizer.tokenizer
            ):
                self.transformer_model.resize_token_embeddings(len(tokenizer.tokenizer))
        except NotImplementedError:
            logger.warning(
                "Could not resize the token embedding matrix of the transformer model. "
                "This model does not support resizing."
            )

        # 调整token类型嵌入大小
        try:
            old_embeddings = self.transformer_model.embeddings.token_type_embeddings
            if old_embeddings.weight.shape[0] != type_vocab_size:
                new_embeddings = self.transformer_model._get_resized_embeddings(old_embeddings, type_vocab_size)
                
                self.transformer_model.embeddings.token_type_embeddings = new_embeddings
                self.transformer_model.config.type_vocab_size = type_vocab_size
                self.transformer_model.type_vocab_size = type_vocab_size

        except NotImplementedError:
            logger.warning(
                "Could not resize the token type embedding matrix of the transformer model. "
                "This model does not support resizing."
            )

        # 设置特殊token的数量
        self._num_added_start_tokens = len(tokenizer.single_sequence_start_tokens)
        self._num_added_end_tokens = len(tokenizer.single_sequence_end_tokens)
        self._num_added_tokens = self._num_added_start_tokens + self._num_added_end_tokens

        # 设置训练参数
        self.train_parameters = train_parameters
        if not train_parameters:
            for param in self.transformer_model.parameters():
                param.requires_grad = False

        self.eval_mode = eval_mode
        if eval_mode:
            self.transformer_model.eval()

    @overrides
    def train(self, mode: bool = True):
        """
        设置模型的训练模式。
        
        参数:
        mode: bool - 是否设置为训练模式
        
        返回:
        self - 返回模型本身以支持链式调用
        """
        self.training = mode
        for name, module in self.named_children():
            if self.eval_mode and name == "transformer_model":
                module.eval()
            else:
                module.train(mode)
        return self

    @overrides
    def get_output_dim(self):
        """
        获取输出维度。
        
        返回:
        int - 模型的隐藏层大小
        """
        return self.output_dim

    def _number_of_token_type_embeddings(self):
        """
        获取token类型嵌入的数量。
        
        返回:
        int - token类型嵌入的数量
        """
        if isinstance(self.config, XLNetConfig):
            return 3  # XLNet有3个类型ID
        elif hasattr(self.config, "type_vocab_size"):
            return self.config.type_vocab_size
        else:
            return 0

    @overrides
    def forward(
        self,
        token_ids: torch.LongTensor,
        mask: torch.BoolTensor,
        type_ids: Optional[torch.LongTensor] = None,
        segment_concat_mask: Optional[torch.BoolTensor] = None,
    ) -> torch.Tensor:  # type: ignore
        """
        前向传播函数。
        
        参数:
        token_ids: torch.LongTensor
            形状: [batch_size, num_wordpieces] 或 [batch_size, num_segment_concat_wordpieces]
        mask: torch.BoolTensor
            形状: [batch_size, num_wordpieces]
        type_ids: Optional[torch.LongTensor]
            形状: [batch_size, num_wordpieces] 或 [batch_size, num_segment_concat_wordpieces]
        segment_concat_mask: Optional[torch.BoolTensor]
            形状: [batch_size, num_segment_concat_wordpieces]
            
        返回:
        torch.Tensor - 形状: [batch_size, num_wordpieces, embedding_size]
        """
        # 处理type_ids
        if type_ids is not None:
            max_type_id = type_ids.max()
            if max_type_id == 0:
                type_ids = None
            else:
                if max_type_id >= self._number_of_token_type_embeddings():
                    raise ValueError("Found type ids too large for the chosen transformer model.")
                assert token_ids.shape == type_ids.shape

        # 处理长序列
        fold_long_sequences = self._max_length is not None and token_ids.size(1) > self._max_length
        if fold_long_sequences:
            batch_size, num_segment_concat_wordpieces = token_ids.size()
            token_ids, segment_concat_mask, type_ids = self._fold_long_sequences(
                token_ids, segment_concat_mask, type_ids
            )

        # 准备transformer输入
        transformer_mask = segment_concat_mask if self._max_length is not None else mask
        assert transformer_mask is not None
        # Shape: [batch_size, num_wordpieces, embedding_size],
        # or if self._max_length is not None:
        # [batch_size * num_segments, self._max_length, embedding_size]

        # We call this with kwargs because some of the huggingface models don't have the
        # token_type_ids parameter and fail even when it's given as None.
        # Also, as of transformers v2.5.1, they are taking FloatTensor masks.
        parameters = {"input_ids": token_ids, "attention_mask": transformer_mask.float()}
        if type_ids is not None:
            parameters["token_type_ids"] = type_ids

        # 获取transformer输出
        transformer_output = self.transformer_model(**parameters)
        if self._scalar_mix is not None:
            # The hidden states will also include the embedding layer, which we don't
            # include in the scalar mix. Hence the `[1:]` slicing.
            hidden_states = transformer_output.hidden_states[1:]
            embeddings = self._scalar_mix(hidden_states)
        else:
            embeddings = transformer_output.last_hidden_state

        # 处理长序列的展开
        if fold_long_sequences:
            embeddings = self._unfold_long_sequences(
                embeddings, segment_concat_mask, batch_size, num_segment_concat_wordpieces
            )

        return embeddings

    def _fold_long_sequences(
        self,
        token_ids: torch.LongTensor,
        mask: torch.BoolTensor,
        type_ids: Optional[torch.LongTensor] = None,
    ) -> Tuple[torch.LongTensor, torch.LongTensor, Optional[torch.LongTensor]]:
        """
        将长序列折叠成多个段。
        [ [CLS] A B C [SEP] [CLS] D E [SEP] ]
        -> [ [ [CLS] A B C [SEP] ], [ [CLS] D E [SEP] [PAD] ] ]
        The [PAD] positions can be found in the returned `mask`.
        
        参数:
        token_ids: torch.LongTensor
            形状: [batch_size, num_segment_concat_wordpieces]
        mask: torch.BoolTensor
            形状: [batch_size, num_segment_concat_wordpieces]
        type_ids: Optional[torch.LongTensor]
            形状: [batch_size, num_segment_concat_wordpieces]
            
        返回:
        Tuple[torch.LongTensor, torch.LongTensor, Optional[torch.LongTensor]]
            - 折叠后的token_ids
            - 折叠后的mask
            - 折叠后的type_ids（如果提供）
        """
        num_segment_concat_wordpieces = token_ids.size(1)
        num_segments = math.ceil(num_segment_concat_wordpieces / self._max_length)  # type: ignore
        padded_length = num_segments * self._max_length  # type: ignore
        length_to_pad = padded_length - num_segment_concat_wordpieces

        def fold(tensor):  # Shape: [batch_size, num_segment_concat_wordpieces]
            # Shape: [batch_size, num_segments * self._max_length]
            tensor = F.pad(tensor, [0, length_to_pad], value=0)
            # Shape: [batch_size * num_segments, self._max_length]
            return tensor.reshape(-1, self._max_length)

        return fold(token_ids), fold(mask), fold(type_ids) if type_ids is not None else None

    def _unfold_long_sequences(
        self,
        embeddings: torch.FloatTensor,
        mask: torch.BoolTensor,
        batch_size: int,
        num_segment_concat_wordpieces: int,
    ) -> torch.FloatTensor:
        """
        将折叠的长序列展开回原始形式。
        [ [ [CLS]_emb A_emb B_emb C_emb [SEP]_emb ], [ [CLS]_emb D_emb E_emb [SEP]_emb [PAD]_emb ] ]
        -> [ [CLS]_emb A_emb B_emb C_emb D_emb E_emb [SEP]_emb ]
        
        参数:
        embeddings: torch.FloatTensor
            形状: [batch_size * num_segments, self._max_length, embedding_size]
        mask: torch.BoolTensor
            形状: [batch_size * num_segments, self._max_length]
        batch_size: int
            原始批次大小
        num_segment_concat_wordpieces: int
            原始序列长度
            
        返回:
        torch.FloatTensor - 形状: [batch_size, num_wordpieces, embedding_size]
        """
        def lengths_to_mask(lengths, max_len, device):
            return torch.arange(max_len, device=device).expand(
                lengths.size(0), max_len
            ) < lengths.unsqueeze(1)

        device = embeddings.device
        num_segments = int(embeddings.size(0) / batch_size)
        embedding_size = embeddings.size(2)

        # 计算实际token数量
        num_wordpieces = num_segment_concat_wordpieces - (num_segments - 1) * self._num_added_tokens

        # 重塑张量
        embeddings = embeddings.reshape(
            batch_size, num_segments * self._max_length, embedding_size  # type: ignore
        )
        mask = mask.reshape(batch_size, num_segments * self._max_length)  # type: ignore
        # We assume that all 1s in the mask precede all 0s, and add an assert for that.
        # Open an issue on GitHub if this breaks for you.
        # Shape: (batch_size,)
        seq_lengths = mask.sum(-1)
        if not (lengths_to_mask(seq_lengths, mask.size(1), device) == mask).all():
            raise ValueError(
                "Long sequence splitting only supports masks with all 1s preceding all 0s."
            )
            
        # 计算结束token索引
        end_token_indices = (
            seq_lengths.unsqueeze(-1) - torch.arange(self._num_added_end_tokens, device=device) - 1
        )

        # 提取开始和结束token的嵌入
        start_token_embeddings = embeddings[:, : self._num_added_start_tokens, :]
        end_token_embeddings = batched_index_select(embeddings, end_token_indices)

        # 处理段级token
        embeddings = embeddings.reshape(batch_size, num_segments, self._max_length, embedding_size)
        embeddings = embeddings[
            :, :, self._num_added_start_tokens : embeddings.size(2) - self._num_added_end_tokens, :
        ]  # truncate segment-level start/end tokens
        embeddings = embeddings.reshape(batch_size, -1, embedding_size)  # flatten

        # 处理结束token
        num_effective_segments = (seq_lengths + self._max_length - 1) // self._max_length
        # The number of indices that end tokens should shift back.
        num_removed_non_end_tokens = (
            num_effective_segments * self._num_added_tokens - self._num_added_end_tokens
        )
        # Shape: (batch_size, self._num_added_end_tokens)
        end_token_indices -= num_removed_non_end_tokens.unsqueeze(-1)
        assert (end_token_indices >= self._num_added_start_tokens).all()
        # Add space for end embeddings
        embeddings = torch.cat([embeddings, torch.zeros_like(end_token_embeddings)], 1)
        # Add end token embeddings back
        embeddings.scatter_(
            1, end_token_indices.unsqueeze(-1).expand_as(end_token_embeddings), end_token_embeddings
        )

        # 添加开始token
        embeddings = torch.cat([start_token_embeddings, embeddings], 1)

        # Truncate to original length
        embeddings = embeddings[:, :num_wordpieces, :]
        return embeddings
