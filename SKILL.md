---
name: csv-encoding-converter
description: 自动检测CSV文件编码并转换为UTF-8，解决Excel打开中文乱码问题。支持GBK/GB2312/GB18030/UTF-8-SIG/Latin-1等编码自动识别。
triggers: ["csv乱码", "转换csv编码", "gbk转utf8", "修复csv中文", "csv编码转换"]
permissions: ["file:read", "file:write", "ipython:execute"]
author: user
version: 1.0.0
---

# CSV 编码转换器

## 功能说明
自动检测上传的 CSV 文件编码格式，将其转换为标准 UTF-8 编码（无 BOM），解决中文乱码问题。

## 触发条件
- 用户上传 CSV 文件并提到"乱码"、"编码"、"中文显示错误"
- 用户输入关键词："csv转utf8"、"修复编码"、"gbk转utf8"

## 执行流程

### 步骤 1：接收文件
获取用户提供的文件路径，检查文件是否存在且为 CSV 格式。

### 步骤 2：编码检测
使用 `chardet` 库检测文件编码，置信度需 &gt;70%。

### 步骤 3：读取与转换
- 使用检测到的编码读取 CSV
- 转换为 pandas DataFrame
- 保存为 UTF-8 编码（无 BOM）到 `/mnt/kimi/output/`

### 步骤 4：结果反馈
- 显示原始编码
- 显示转换后文件路径
- 预览前 3 行内容确认中文正常

## 代码实现
执行 `main.py` 中的 `convert_csv_encoding(file_path)` 函数。

## 异常处理
- **检测失败**：尝试常见中文编码（gb18030 &gt; gbk &gt; utf-8-sig）
- **文件过大**：使用 chunksize 分块读取（&gt;10MB）
- **读取错误**：使用 `errors='replace'` 跳过损坏字符并记录

## 使用示例

**用户**：我的文件 `/mnt/kimi/upload/data.csv` 打开中文是乱码

**Claw 执行**：
1. 检测编码 → GB2312 (置信度 98%)
2. 读取 1500 行，12 列
3. 转换并保存 → `/mnt/kimi/output/data_utf8.csv`
4. 返回预览确认中文正常
