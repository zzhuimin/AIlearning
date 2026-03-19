---
name: openclaw-security-auditor
display_name: 🔒 OpenClaw 安全加固审计器
description: 全面的 OpenClaw 安全评估与加固工具，支持 CVE 漏洞扫描、配置基线检查、供应链风险评估和自动加固建议生成。适配 2026 年最新安全威胁模型。
triggers: ["安全审计", "安全扫描", "CVE扫描", "漏洞检查", "OpenClaw安全", "安全加固", "基线检查", "风险评估"]
permissions: ["read:file", "write:file", "execute:shell", "network:http", "system:info"]
author: SecurityOps-Community
version: 1.0.0
min_openclaw_version: "2026.1.29"
---

# 🔒 OpenClaw 安全加固审计器

## 概述

这是一个专业的 OpenClaw 安全审计技能，基于七层安全模型提供全面的安全评估。技能包括 CVE 漏洞扫描、配置基线检查、供应链风 险评估和自动加固建议生成。

## 核心功能

- **🚨 CVE 实时扫描**: 自动检测 2026 年最新高危漏洞 (CVE-2026-25253, CVE-2026-24763 等)
- **🛡️ 七层基线审计**: 基于 OpenClaw Security Practice Guide 的完整安全检查
- **🔍 供应链分析**: 审查已安装 Skills 的权限和来源，识别恶意包
- **📊 自动化报告**: 生成包含风险评分、修复命令的 Markdown/HTML 报告
- **⚡ 一键加固**: 提供可直接执行的加固脚本（需用户审批）

## 技能触发的方法
- "帮我做个安全审计"
- "扫描一下OpenClaw的CVE漏洞"
- "检查一下我的OpenClaw安全配置"
- "执行安全加固扫描"
- "做一次全面的风险评估"

## 交互示例对话用户
- "帮我做个OpenClaw安全审计"

## 文件结构

技能包含以下文件：

- `skill.json` - 技能元数据和配置
- `README.md` - 技能说明文档
- `config/security_checks.yaml` - 安全检查配置
- `templates/audit_report.md` - 审计报告模板

## 使用方法

当用户提及以下关键词时触发技能：
- 安全审计
- 安全扫描
- CVE扫描
- 漏洞检查
- OpenClaw安全
- 安全加固
- 基线检查
- 风险评估

## 执行流程

### Phase 1: 环境信息采集
通过交互式问卷收集环境信息：
1. OpenClaw 版本号
2. 部署模式（Docker/Kubernetes/Bare-metal）
3. 当前 Gateway 绑定地址
4. 认证模式
5. 已安装 Skills 情况
6. 网络暴露情况

### Phase 2: CVE 漏洞扫描（紧急）
检查以下 2026 年高危 CVE：
- CVE-2026-25253 (CVSS 8.8): WebSocket RCE
- CVE-2026-24763 (CVSS 7.8): Docker 沙箱命令注入
- CVE-2026-25157 (CVSS 7.5): SSH 模式命令注入
- CVE-2026-25593 (CVSS 6.5): ClawJacked Gateway 暴力破解

### Phase 3: 七层安全基线检查
逐层执行安全检查：
1. 网关绑定安全
2. 认证安全
3. 网络安全
4. 容器隔离
5. 运行时防护
6. 凭据管理
7. 监控审计

### Phase 4: 供应链安全审计
- 列出所有已安装 Skills 及其权限
- 标记需要高危权限的 Skills
- 检查已知恶意 Skills

### Phase 5: 生成报告
生成包含以下内容的审计报告：
1. 执行摘要和总体评分
2. 漏洞详情
3. 加固指南
4. 合规检查表

## 配置

可在 `skill.json` 中配置：
- `audit_level`: basic/standard/comprehensive
- `check_cves`: 要检查的 CVE 列表
- `gateway_bind`: 期望的 Gateway 绑定地址
- `strict_mode`: 是否启用严格模式

## 注意事项

1. 所有敏感操作都需要用户明确批准
2. 只读检查会先执行，不会修改系统
3. 加固操作需要用户确认后才执行
4. 提供完整的回滚方案

## 输出示例

```
# OpenClaw 安全审计报告
**审计时间**: 2026-03-19 16:48 GMT+8
**目标版本**: OpenClaw 2026.1.30
**总体评分**: 85/100 (良好)

## 🚨 紧急发现 (P0)
无紧急风险

## 📊 七层安全基线检查
| 层级 | 检查项 | 状态 | 备注 |
|------|--------|------|------|
| Layer 1 | 网关绑定 | ✅ 通过 | 绑定到 127.0.0.1 |
| Layer 2 | 认证配置 | ✅ 通过 | Token 认证已启用 |
| ... | ... | ... | ... |

## 🔧 立即加固命令
```bash
# 加固建议
echo "安全配置已优化"
```

## 📋 详细发现
详细的安全检查结果...
```

## 版本要求

需要 OpenClaw 版本 >= 2026.1.29