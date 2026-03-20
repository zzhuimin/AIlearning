# PureTextOutputSkill - OpenClaw 纯文本输出技能

## 1. 技能概述
### 1.1 功能
解决 OpenClaw 聊天窗口输出的 JSON 嵌套格式问题（如 `[{'type': 'text', 'text': "[{'type': 'text', 'text': 'xxx'}]"}]`），自动提取核心纯文本内容，剔除所有格式包装和逃逸字符，仅输出纯文本。

### 1.2 解决的问题
- JSON 多层嵌套格式冗余
- 单/双引号混合导致的解析错误
- 转义字符（`\uXXXX`、`\\n` 等）显示异常
- 格式字段（`type/text`）冗余包装

### 1.3 核心特性
- 兼容字符串/列表/字典三种输入格式
- 递归解析任意层级的嵌套结构
- 自动清洗特殊字符和格式符号
- 容错处理：解析失败时返回清洗后的原内容
- 兼容 Python 3.6+ 版本

## 2. 安装部署
### 2.1 环境要求
- Python 3.6+
- OpenClaw 支持 Python 插件扩展
- 依赖包：`json5>=0.9.14`、`regex>=2023.12.25`

### 2.2 安装步骤
#### 方式1：源码安装
```bash
# 克隆/解压技能包
cd openclaw-pure-text-skill

# 安装依赖
pip install -r requirements.txt  # 若没有requirements.txt，执行：pip install json5 regex

# 安装技能包
python setup.py install