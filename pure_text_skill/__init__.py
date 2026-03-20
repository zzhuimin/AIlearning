"""
OpenClaw 纯文本输出Skill
功能：解析嵌套JSON/字典格式，提取核心纯文本内容，解决输出格式嵌套和逃逸问题
"""
from .core import PureTextOutputSkill

__version__ = "1.0.0"
__all__ = ["PureTextOutputSkill"]