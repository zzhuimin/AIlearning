&lt;!-- 
  OpenClaw 安全加固审计报告模板
  变量说明:
  {{timestamp}} - 审计执行时间
  {{target_version}} - 目标 OpenClaw 版本
  {{audit_type}} - 审计类型 (quick_scan/full_audit/auto_remediate)
  {{overall_score}} - 总体安全评分 (0-100)
  {{risk_level}} - 风险等级 (Critical/High/Medium/Low)
  {{hostname}} - 目标主机名/IP
--&gt;

&lt;div align="center"&gt;

# 🔒 OpenClaw 安全加固审计报告

**机密等级**: 内部使用 🔴  
**报告编号**: OC-AUDIT-{{report_id}}  
**生成时间**: {{timestamp}}  
**审计模式**: {{audit_type}}

&lt;/div&gt;

---

## 📋 执行摘要 (Executive Summary)

| 评估项目 | 详情 |
|---------|------|
| **审计目标** | {{hostname}} (OpenClaw {{target_version}}) |
| **总体评分** | &lt;span style="color: {{score_color}}"&gt;{{overall_score}}/100&lt;/span&gt; |
| **风险等级** | {{risk_level}} {{risk_emoji}} |
| **发现漏洞** | 紧急: {{critical_count}} | 高危: {{high_count}} | 中危: {{medium_count}} | 低危: {{low_count}} |
| **合规状态** | {{compliance_status}} |
| **建议措施** | {{primary_recommendation}} |

### 🎯 关键发现
{{executive_summary}}

---

## 🚨 紧急漏洞分析 (Critical CVEs)

&lt;!-- 如果有 CVE 发现，循环填充此区块 --&gt;
{{#each cve_findings}}
### {{cve_id}} (CVSS {{cvss_score}})
- **严重程度**: {{severity}} {{#if is_critical}}🔴{{/if}}
- **漏洞类型**: {{vuln_type}}
- **影响版本**: {{affected_versions}}
- **当前状态**: {{status}} {{#if is_vulnerable}}❌ 受影响{{else}}✅ 已修复{{/if}}
- **利用难度**: {{exploit_difficulty}}
- **修复版本**: {{fix_version}}

**漏洞描述**:  
{{description}}

**检测方法**:  
```bash
{{check_command}}