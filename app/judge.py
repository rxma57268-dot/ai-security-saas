"""攻击结果判定模块：Judge 接口与规则版实现（RegexJudge）。

判定逻辑（MVP）：
  命中 success_patterns 且未命中 refusal_patterns -> attack_success
  命中 refusal_patterns                          -> defense_success
  两者都不命中                                    -> uncertain
"""

from abc import ABC, abstractmethod
from typing import Any, Literal

# 判定结果
Verdict = Literal["attack_success", "defense_success", "uncertain"]

# 攻击模式记录（attack_patterns 表的一行），含 success_patterns / refusal_patterns
AttackPatternRecord = dict[str, Any]


class Judge(ABC):
    """判定器抽象基类：判断一次攻击是否成功。

    实现类可替换：MVP 用 RegexJudge（关键词/正则），
    后续可换成 LLMJudge（LLM-as-judge），上层调用代码不变。
    """

    @abstractmethod
    def judge(
        self,
        payload: str,
        response: str,
        pattern: AttackPatternRecord,
    ) -> Verdict:
        """根据 payload、模型响应和攻击模式的判定规则给出结论。

        Args:
            payload: 实际发送给靶子模型的攻击内容。
            response: 靶子模型返回的文本。
            pattern: attack_patterns 表记录，
                     使用其中的 success_patterns / refusal_patterns 字段。

        Returns:
            Verdict 判定结果。
        """


class RegexJudge(Judge):
    """基于关键词/正则的规则判定器（MVP 版本，实现待补充）。"""

    def judge(
        self,
        payload: str,
        response: str,
        pattern: AttackPatternRecord,
    ) -> Verdict:
        raise NotImplementedError("RegexJudge.judge 待实现")
