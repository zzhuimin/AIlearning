# 🔒 OpenClaw Security Auditor Skill

**版本**: 1.0.0  
**适配 OpenClaw 版本**: &gt;= 2026.1.29  
**最后更新**: 2026-04-01

专为安全运营团队设计的 端口扫描工具，使用rustscan 工具。

## ✨ 核心功能

- 🚨 **端口扫描**: 自动检测 2026 年最新高危漏洞 (CVE-2026-25253, CVE-2026-24763 等)
- 🛡️ **七层基线审计**: 基于 OpenClaw Security Practice Guide 的完整安全检查
- 🔍 **供应链分析**: 审查已安装 Skills 的权限和来源，识别 ClawHub 恶意包
- 📊 **自动化报告**: 生成包含风险评分、修复命令的 Markdown/HTML 报告
- ⚡ **一键加固**: 提供可直接执行的加固脚本 (需审批)

## 🚀 快速开始

### 安装步骤

1. **克隆 Skill 到 OpenClaw 目录**:

```bash
cd /path/to/openclaw
mkdir -p skills/openclaw-security-auditor
cd skills/openclaw-security-auditor

# 下载 Skill 文件
curl -O https://raw.githubusercontent.com/your-repo/openclaw-security/main/skill.json
curl -O https://raw.githubusercontent.com/your-repo/openclaw-security/main/config/security_checks.yaml