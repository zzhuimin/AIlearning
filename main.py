#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CSV 编码转换器 - 主执行脚本
自动检测并转换 CSV 文件编码为 UTF-8
"""

import os
import sys
import chardet
import pandas as pd
from pathlib import Path

def detect_encoding(file_path: str, sample_size: int = 100000) -> tuple:
    """
    检测文件编码
    返回: (encoding, confidence)
    """
    try:
        with open(file_path, 'rb') as f:
            raw_data = f.read(sample_size)
            result = chardet.detect(raw_data)
            encoding = result.get('encoding', 'utf-8')
            confidence = result.get('confidence', 0)
            
            # 处理 chardet 常见的误判
            if encoding and encoding.lower() == 'gb2312':
                # GB18030 兼容 GB2312，建议升级
                encoding = 'gb18030'
            elif encoding and encoding.lower() == 'iso-8859-1':
                # 可能是 Latin-1，但也可能是其他编码
                pass
                
            return encoding, confidence
    except Exception as e:
        return None, 0.0

def read_csv_with_fallback(file_path: str, detected_encoding: str) -> pd.DataFrame:
    """
    使用检测到的编码读取 CSV，失败则尝试备用编码
    """
    encodings_to_try = [detected_encoding] if detected_encoding else []
    
    # 常见中文编码备用列表（按优先级）
    fallback_encodings = ['gb18030', 'gbk', 'gb2312', 'utf-8-sig', 'utf-8', 'big5', 'latin-1']
    
    # 去重，保持顺序
    for enc in fallback_encodings:
        if enc not in encodings_to_try:
            encodings_to_try.append(enc)
    
    last_error = None
    
    for encoding in encodings_to_try:
        try:
            print(f"尝试使用编码: {encoding}")
            # 使用 error_bad_lines=False (旧版pandas) 或 on_bad_lines='skip' (新版)
            try:
                df = pd.read_csv(file_path, encoding=encoding, on_bad_lines='skip')
            except TypeError:
                # 兼容旧版 pandas
                df = pd.read_csv(file_path, encoding=encoding, error_bad_lines=False)
            
            print(f"✅ 成功使用 {encoding} 读取，共 {len(df)} 行，{len(df.columns)} 列")
            return df, encoding
            
        except Exception as e:
            last_error = e
            print(f"❌ {encoding} 失败: {str(e)[:100]}")
            continue
    
    raise Exception(f"所有编码尝试失败，最后错误: {last_error}")

def convert_csv_encoding(file_path: str, add_bom: bool = False) -> dict:
    """
    主转换函数
    返回结果字典
    """
    result = {
        "success": False,
        "original_encoding": None,
        "detected_confidence": 0,
        "output_path": None,
        "rows": 0,
        "columns": 0,
        "preview": None,
        "error": None
    }
    
    try:
        # 1. 验证文件
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"文件不存在: {file_path}")
        
        file_size = os.path.getsize(file_path)
        print(f"📄 文件: {os.path.basename(file_path)}")
        print(f"📦 大小: {file_size / 1024:.2f} KB")
        
        # 2. 检测编码
        print("\n🔍 检测编码中...")
        detected_enc, confidence = detect_encoding(file_path)
        
        if detected_enc:
            print(f"🔍 检测到编码: {detected_enc} (置信度: {confidence:.1%})")
            result["original_encoding"] = detected_enc
            result["detected_confidence"] = confidence
            
            if confidence < 0.6:
                print("⚠️ 置信度较低，将尝试多种编码...")
        else:
            print("⚠️ 编码检测失败，将尝试备用编码...")
        
        # 3. 读取文件
        print("\n📖 读取文件...")
        df, used_encoding = read_csv_with_fallback(file_path, detected_enc)
        
        result["rows"] = len(df)
        result["columns"] = len(df.columns)
        
        # 4. 生成输出路径
        input_path = Path(file_path)
        output_filename = f"{input_path.stem}_utf8{input_path.suffix}"
        output_dir = "/mnt/kimi/output"
        
        # 确保输出目录存在
        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, output_filename)
        
        # 5. 保存为 UTF-8
        encoding_utf8 = 'utf-8-sig' if add_bom else 'utf-8'
        df.to_csv(output_path, index=False, encoding=encoding_utf8)
        
        result["output_path"] = output_path
        result["success"] = True
        
        # 6. 生成预览（前3行）
        preview_df = df.head(3)
        result["preview"] = preview_df.to_string(index=False)
        
        # 7. 打印结果
        print("\n" + "="*50)
        print("✅ 转换成功！")
        print("="*50)
        print(f"原始编码: {used_encoding}")
        print(f"输出编码: {encoding_utf8} {'(带BOM)' if add_bom else '(无BOM)'}")
        print(f"输出路径: {output_path}")
        print(f"数据行数: {len(df)} 行, {len(df.columns)} 列")
        print(f"列名: {list(df.columns)}")
        print("\n📋 预览（前3行）:")
        print(result["preview"])
        print("="*50)
        
        return result
        
    except Exception as e:
        result["error"] = str(e)
        print(f"\n❌ 转换失败: {e}")
        return result

def batch_convert(directory: str, pattern: str = "*.csv") -> list:
    """
    批量转换目录中的 CSV 文件
    """
    results = []
    import glob
    
    files = glob.glob(os.path.join(directory, pattern))
    print(f"找到 {len(files)} 个文件待转换...")
    
    for file_path in files:
        print(f"\n处理: {os.path.basename(file_path)}")
        result = convert_csv_encoding(file_path)
        results.append(result)
    
    # 统计
    success_count = sum(1 for r in results if r["success"])
    print(f"\n批量处理完成: {success_count}/{len(results)} 成功")
    
    return results

# 如果直接运行此脚本
if __name__ == "__main__":
    if len(sys.argv) > 1:
        file_path = sys.argv[1]
        convert_csv_encoding(file_path)
    else:
        print("用法: python main.py <csv_file_path>")
        print("或在 Kimi Claw 中调用 convert_csv_encoding('/path/to/file.csv')")
