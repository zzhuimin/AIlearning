# 企业级中间件漏洞三维检测方案模板

> **Skill名称**: middleware-vuln-intelligence  
> **用途**: 为中间件漏洞提供可落地的检测方案  
> **三维检测**: 网络层资产发现 | 应用层POC验证 | 主机层HIDS/EDR监控

---

## 1. 网络层 - 资产发现模板

### 1.1 中间件默认端口映射表

| 中间件 | 默认端口 | 协议 | 用途说明 |
|--------|----------|------|----------|
| **Tomcat** | 8080 | HTTP | Web服务端口 |
| | 8009 | AJP | AJP连接器端口 |
| | 8005 | Shutdown | 关闭端口 |
| **WebLogic** | 7001 | HTTP/T3 | 默认管理端口 |
| | 7002 | HTTPS/T3S | SSL管理端口 |
| | 5556 | Node Manager | 节点管理器 |
| **Nginx** | 80 | HTTP | 默认HTTP端口 |
| | 443 | HTTPS | 默认HTTPS端口 |
| **Redis** | 6379 | Redis | 默认服务端口 |
| **Kafka** | 9092 | Kafka | 默认监听端口 |
| | 2181 | ZooKeeper | 依赖ZK端口 |
| **Elasticsearch** | 9200 | HTTP | REST API端口 |
| | 9300 | TCP | 节点通信端口 |
| **MongoDB** | 27017 | MongoDB | 默认服务端口 |
| | 27018 | MongoDB | 分片端口 |
| **MySQL** | 3306 | MySQL | 默认服务端口 |
| **PostgreSQL** | 5432 | PostgreSQL | 默认服务端口 |
| **RabbitMQ** | 5672 | AMQP | 消息队列端口 |
| | 15672 | HTTP | 管理界面端口 |
| | 25672 | Erlang | 集群通信端口 |
| **ActiveMQ** | 61616 | OpenWire | 默认消息端口 |
| | 8161 | HTTP | 管理控制台端口 |
| **Docker** | 2375 | HTTP | 未加密API端口 |
| | 2376 | HTTPS | 加密API端口 |
| **Zookeeper** | 2181 | ZK | 客户端端口 |
| | 2888 | ZK | 集群通信端口 |
| | 3888 | ZK | 选举端口 |
| **Jenkins** | 8080 | HTTP | 默认Web端口 |
| **Jupyter** | 8888 | HTTP | 默认Notebook端口 |
| **Kibana** | 5601 | HTTP | 默认Web端口 |
| **Hadoop** | 50070 | HTTP | NameNode Web |
| | 8088 | HTTP | YARN ResourceManager |
| **Spark** | 8080 | HTTP | Master Web UI |
| | 4040 | HTTP | Application UI |

---

### 1.2 Banner指纹模板

#### HTTP Server头指纹识别

```
# Tomcat指纹
Server: Apache-Coyote/1.1
Server: Apache Tomcat/8.5.XX
X-Powered-By: Servlet/3.1 JSP/2.3

# WebLogic指纹
Server: WebLogic Server 12.2.1.4.0
X-Powered-By: Servlet/3.1 JSP/2.3

# Nginx指纹
Server: nginx/1.18.0
Server: nginx/1.21.0

# Apache HTTPD指纹
Server: Apache/2.4.41 (Ubuntu)
Server: Apache/2.4.6 (CentOS)

# IIS指纹
Server: Microsoft-IIS/10.0
X-Powered-By: ASP.NET

# JBoss/WildFly指纹
Server: WildFly/18
X-Powered-By: Undertow/1

# Jetty指纹
Server: Jetty(9.4.35.v20201120)

# Node.js指纹
Server: Express
X-Powered-By: Express
```

#### 协议特征指纹

```
# Redis未授权访问
请求: *1\r\n$4\r\ninfo\r\n
响应: +PONG 或 $XX\r\nredis_version:6.0.9

# MongoDB未授权访问
请求: {isMaster: 1}
响应: {"ismaster": true, "maxBsonObjectSize": 16777216}

# Elasticsearch
请求: GET /_cluster/health
响应: {"cluster_name":"elasticsearch","status":"green"}

# Memcached
请求: stats\r\n
响应: STAT pid 1234\r\nSTAT uptime 3600

# ZooKeeper
请求: envi\n
响应: Environment: zookeeper.version=3.6.2

# Docker API
请求: GET /version
响应: {"Version":"20.10.7","ApiVersion":"1.41"}

# Kafka
请求: 元数据请求(0x0003)
响应: 包含broker列表的元数据

# ActiveMQ
请求: GET /api/jolokia/read/org.apache.activemq:type=Broker,brokerName=localhost
响应: {"value":{"BrokerId":"localhost"}}

# RabbitMQ Management
请求: GET /api/overview
响应: {"rabbitmq_version":"3.8.9","cluster_name":"rabbit@localhost"}

# Java RMI/JRMP
特征: 0x4a524d50 (JRMP魔数)
响应: 包含RMI注册表信息

# Java JMX RMI
端口: 1099, 1098
特征: javax.management.remote.rmi
```

---

### 1.3 端口扫描命令模板

#### Nmap扫描模板

```bash
#!/bin/bash
# ============================================
# Nmap中间件端口扫描脚本
# ============================================

# 基础版本探测
nmap -sV -p 80,443,8080,8443,7001,7002,9092,9200,9300,6379,27017,3306,5432,5672,15672,61616,8161,2375,2376,2181,8888,5601,50070,8088 $TARGET

# 全端口TCP扫描
nmap -sS -p- --open -T4 -oA full_tcp_scan $TARGET

# UDP端口扫描
nmap -sU --top-ports 100 --open -T4 $TARGET

# 中间件指纹识别
nmap -sV --script=http-server-header,http-title,banner -p 80,443,8080,7001 $TARGET

# Redis专项扫描
nmap -p 6379 --script=redis-info $TARGET

# MongoDB专项扫描
nmap -p 27017 --script=mongodb-info $TARGET

# Elasticsearch专项扫描
nmap -p 9200 --script=http-elasticsearch-nodes $TARGET

# Docker API扫描
nmap -p 2375,2376 --script=http-docker-version $TARGET

# 漏洞扫描脚本
nmap -p 8080 --script=http-vuln-cve2017-5638 $TARGET  # Struts2
nmap -p 7001 --script=weblogic-t3-info $TARGET        # WebLogic
nmap -p 9200 --script=http-vuln-cve2015-1427 $TARGET  # Elasticsearch

# 批量扫描（从文件读取目标）
nmap -iL targets.txt -sV -p 80,443,8080,7001,6379,9200 --open -oG scan_results.grep

# 输出格式说明
# -oN: 普通文本输出
# -oX: XML格式输出
# -oG: Grepable格式
# -oA: 输出所有格式
```

#### Masscan快速扫描模板

```bash
#!/bin/bash
# ============================================
# Masscan快速端口扫描脚本
# ============================================

# 基础用法 - 扫描指定端口
masscan -p80,443,8080,7001,6379,9200,27017,3306,2375 192.168.1.0/24 --rate=1000

# 扫描常见中间件端口
masscan -p80,443,8080-8090,8443,7001-7010,9000-9005,9200,9300,6379,6380,27017,3306,5432,5672,15672,61616,8161,2375,2376,2181,2888,3888,8888,5601,50070,8088 10.0.0.0/8 --rate=10000

# 全端口扫描（高速）
masscan -p0-65535 192.168.1.0/24 --rate=10000 --wait 0

# 排除特定IP
masscan 192.168.1.0/24 -p80,443,8080 --excludefile exclude.txt --rate=5000

# 输出到文件
masscan -p80,443,8080,7001,6379 192.168.1.0/24 --rate=10000 -oL scan_results.txt

# 从文件读取目标列表
masscan -iL targets.txt -p80,443,8080 --rate=5000 -oJ results.json

# 配合Nmap进行服务识别
# 第一步：Masscan快速发现开放端口
masscan -p0-65535 192.168.1.0/24 --rate=10000 -oL masscan_results.txt
# 第二步：提取端口并生成Nmap命令
awk '{print $3}' masscan_results.txt | sort -u | tr '\n' ',' > ports.txt
# 第三步：Nmap服务识别
nmap -sV -p $(cat ports.txt) -iL targets.txt

# 参数说明
# --rate: 每秒发送数据包数量（默认100）
# --wait: 扫描完成后等待时间（秒）
# -oL: 列表格式输出
# -oJ: JSON格式输出
# -oG: Grepable格式输出
# --excludefile: 排除IP列表文件
```

#### Zmap扫描模板

```bash
#!/bin/bash
# ============================================
# Zmap互联网级端口扫描
# ============================================

# 单端口全网扫描（需要足够带宽）
zmap -p 80 -o results.csv

# 扫描特定网段
zmap -p 6379 192.168.0.0/16 -o redis_scan.csv

# 扫描多个端口（使用ZGrab2配合）
zmap -p 443 --output-fields=saddr,daddr,sport,dport,seqnum,acknum,window --output-module=csv -o https_scan.csv

# 配合ZGrab2进行应用层探测
cat ip_list.txt | zgrab2 http --port 8080 --output-file http_results.json

# Redis探测
cat ip_list.txt | zgrab2 redis --output-file redis_results.json

# TLS证书探测
cat ip_list.txt | zgrab2 tls --port 443 --output-file tls_results.json
```

---

### 1.4 指纹识别脚本（Python）

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
中间件Banner指纹识别脚本
用途：识别目标开放的中间件类型和版本
"""

import socket
import ssl
import json
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

# 中间件指纹库
FINGERPRINTS = {
    "Tomcat": {
        "ports": [8080, 8009, 8005],
        "banners": [b"Apache-Coyote", b"Tomcat", b"JSP/2", b"Servlet/"],
        "paths": ["/", "/manager/html", "/docs"],
        "headers": ["X-Powered-By: Servlet", "Server: Apache-Coyote"]
    },
    "WebLogic": {
        "ports": [7001, 7002, 5556],
        "banners": [b"WebLogic", b"WebLogic Server", b"bea_wls_internal"],
        "paths": ["/console", "/wls-wsat"],
        "headers": ["Server: WebLogic"]
    },
    "Nginx": {
        "ports": [80, 443, 8080],
        "banners": [b"nginx/", b"Server: nginx"],
        "paths": ["/"],
        "headers": ["Server: nginx"]
    },
    "Redis": {
        "ports": [6379, 6380],
        "banners": [b"+PONG", b"redis_version", b"$"],
        "probe": b"*1\r\n$4\r\ninfo\r\n",
        "response_patterns": [b"redis_version"]
    },
    "Elasticsearch": {
        "ports": [9200, 9300],
        "banners": [b"cluster_name", b"elasticsearch"],
        "paths": ["/", "/_cluster/health"],
        "headers": []
    },
    "MongoDB": {
        "ports": [27017, 27018],
        "banners": [b"ismaster", b"maxBsonObjectSize"],
        "probe": b"\x3d\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00",
        "response_patterns": [b"ismaster"]
    },
    "Docker": {
        "ports": [2375, 2376],
        "banners": [b"ApiVersion", b"Docker"],
        "paths": ["/version", "/info"],
        "headers": []
    },
    "Zookeeper": {
        "ports": [2181],
        "banners": [b"zookeeper.version", b"Zookeeper version"],
        "probe": b"envi\n",
        "response_patterns": [b"zookeeper.version"]
    }
}


def grab_banner(target, port, timeout=5):
    """获取服务Banner"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target, port))
        
        # 发送探测数据
        if port in [6379, 6380]:  # Redis
            sock.send(b"INFO\r\n")
        elif port in [27017, 27018]:  # MongoDB
            sock.send(b"\x3d\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00")
        elif port == 2181:  # ZooKeeper
            sock.send(b"envi\n")
        else:
            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        
        banner = sock.recv(1024)
        sock.close()
        return banner
    except Exception as e:
        return None


def identify_service(target, port):
    """识别服务类型"""
    banner = grab_banner(target, port)
    if not banner:
        return None
    
    for service, fp in FINGERPRINTS.items():
        if port in fp.get("ports", []):
            # 检查banner匹配
            for pattern in fp.get("banners", []):
                if pattern in banner:
                    return {"service": service, "port": port, "banner": banner[:200]}
            
            # 检查响应模式匹配
            for pattern in fp.get("response_patterns", []):
                if pattern in banner:
                    return {"service": service, "port": port, "banner": banner[:200]}
    
    return {"service": "unknown", "port": port, "banner": banner[:200]}


def scan_target(target, ports):
    """扫描目标端口"""
    results = []
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(identify_service, target, port): port for port in ports}
        for future in as_completed(futures):
            result = future.result()
            if result:
                results.append(result)
    return results


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <target> [ports]")
        sys.exit(1)
    
    target = sys.argv[1]
    if len(sys.argv) > 2:
        ports = [int(p) for p in sys.argv[2].split(",")]
    else:
        # 默认扫描常见端口
        ports = [80, 443, 8080, 7001, 6379, 9200, 27017, 3306, 2375, 2181]
    
    print(f"[*] Scanning {target}...")
    results = scan_target(target, ports)
    
    for r in results:
        print(f"[+] {r['service']} detected on port {r['port']}")
        print(f"    Banner: {r['banner']}")
```

---


## 2. 应用层 - POC验证模板

### 2.1 Python POC脚本模板

#### 模板A: HTTP通用POC模板

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
[漏洞名称] POC检测脚本
CVE: [CVE编号]
影响组件: [组件名称]
影响版本: [版本范围]
利用条件: [具体条件]

Author: [作者]
Date: [日期]

免责声明: 本脚本仅供授权安全测试使用，严禁用于非法用途
"""

import requests
import sys
import argparse
import urllib3
from urllib.parse import urljoin, urlparse

# 禁用SSL警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class VulnPOC:
    """漏洞检测类"""
    
    def __init__(self, target, port=80, timeout=10, proxy=None):
        """
        初始化POC
        
        Args:
            target: 目标IP或域名
            port: 目标端口
            timeout: 请求超时时间
            proxy: 代理设置，如 http://127.0.0.1:8080
        """
        self.target = target
        self.port = port
        self.timeout = timeout
        self.proxy = {"http": proxy, "https": proxy} if proxy else None
        
        # 构建基础URL
        scheme = "https" if port == 443 else "http"
        self.base_url = f"{scheme}://{target}:{port}"
    
    def check_vuln(self):
        """
        漏洞检测主函数
        
        Returns:
            tuple: (is_vulnerable, details)
                - is_vulnerable: bool，是否存在漏洞
                - details: dict，详细信息
        """
        try:
            # 构造检测Payload
            payload_url = urljoin(self.base_url, "/vulnerable/path")
            
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
                "Connection": "close"
            }
            
            # 发送检测请求
            response = requests.get(
                payload_url,
                headers=headers,
                timeout=self.timeout,
                verify=False,
                proxies=self.proxy,
                allow_redirects=False
            )
            
            # 判断漏洞是否存在
            # 示例1: 基于状态码判断
            if response.status_code == 200:
                # 示例2: 基于响应内容判断
                if "vulnerable_indicator" in response.text:
                    return True, {
                        "url": payload_url,
                        "status_code": response.status_code,
                        "response_length": len(response.text),
                        "evidence": "Found vulnerable indicator in response"
                    }
            
            # 示例3: 需要认证的检测
            if response.status_code == 401:
                return None, {"message": "Authentication required", "url": payload_url}
            
            return False, {"message": "Target does not appear vulnerable"}
            
        except requests.exceptions.ConnectTimeout:
            return None, {"error": "Connection timeout"}
        except requests.exceptions.ConnectionError:
            return None, {"error": "Connection error"}
        except Exception as e:
            return None, {"error": str(e)}
    
    def exploit(self, command=None):
        """
        漏洞利用函数（可选实现）
        
        Args:
            command: 要执行的命令
            
        Returns:
            tuple: (success, result)
        """
        # 实现利用逻辑
        pass
    
    def batch_check(self, target_file):
        """
        批量检测
        
        Args:
            target_file: 包含目标列表的文件路径
        """
        with open(target_file, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]
        
        results = []
        for target_line in targets:
            # 解析目标格式: ip:port 或 ip
            if ':' in target_line:
                ip, port = target_line.split(':')
                port = int(port)
            else:
                ip, port = target_line, self.port
            
            self.target = ip
            self.port = port
            scheme = "https" if port == 443 else "http"
            self.base_url = f"{scheme}://{ip}:{port}"
            
            is_vuln, details = self.check_vuln()
            
            if is_vuln is True:
                print(f"[+] Vulnerable: {ip}:{port}")
                results.append({"target": f"{ip}:{port}", "vulnerable": True, "details": details})
            elif is_vuln is False:
                print(f"[-] Not vulnerable: {ip}:{port}")
            else:
                print(f"[!] Check error: {ip}:{port} - {details.get('error', details.get('message', 'Unknown'))}")
        
        # 保存结果
        with open("scan_results.json", 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"\n[*] Results saved to scan_results.json")
        print(f"[*] Total vulnerable: {len(results)}")


def main():
    """主函数"""
    parser = argparse.ArgumentParser(
        description="[漏洞名称] POC检测工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python poc.py -t 192.168.1.1
    python poc.py -t 192.168.1.1 -p 8080
    python poc.py -f targets.txt
    python poc.py -t 192.168.1.1 --proxy http://127.0.0.1:8080
        """
    )
    
    parser.add_argument('-t', '--target', help='目标IP或域名')
    parser.add_argument('-p', '--port', type=int, default=80, help='目标端口 (默认: 80)')
    parser.add_argument('-f', '--file', help='目标列表文件')
    parser.add_argument('--timeout', type=int, default=10, help='请求超时时间 (默认: 10秒)')
    parser.add_argument('--proxy', help='代理地址，如 http://127.0.0.1:8080')
    parser.add_argument('--threads', type=int, default=10, help='并发线程数 (默认: 10)')
    
    args = parser.parse_args()
    
    if not args.target and not args.file:
        parser.print_help()
        sys.exit(1)
    
    poc = VulnPOC(
        target=args.target or "",
        port=args.port,
        timeout=args.timeout,
        proxy=args.proxy
    )
    
    if args.file:
        poc.batch_check(args.file)
    else:
        is_vuln, details = poc.check_vuln()
        
        if is_vuln is True:
            print(f"[+] Target is VULNERABLE!")
            print(f"    URL: {details.get('url')}")
            print(f"    Status: {details.get('status_code')}")
            print(f"    Evidence: {details.get('evidence')}")
        elif is_vuln is False:
            print(f"[-] Target is NOT vulnerable")
        else:
            error_msg = details.get('error', details.get('message', 'Unknown error'))
            print(f"[!] Check failed: {error_msg}")


if __name__ == '__main__':
    main()
```

---

#### 模板B: Socket原始协议POC模板

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
[协议名称] 协议级POC检测脚本
用途：针对非HTTP协议的原始Socket检测

Author: [作者]
Date: [日期]
"""

import socket
import struct
import sys
import argparse
import ssl


class SocketPOC:
    """Socket协议级POC"""
    
    def __init__(self, target, port, timeout=10, use_ssl=False):
        self.target = target
        self.port = port
        self.timeout = timeout
        self.use_ssl = use_ssl
        self.sock = None
    
    def connect(self):
        """建立连接"""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(self.timeout)
            self.sock.connect((self.target, self.port))
            
            if self.use_ssl:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                self.sock = context.wrap_socket(self.sock, server_hostname=self.target)
            
            return True
        except Exception as e:
            print(f"[!] Connection failed: {e}")
            return False
    
    def disconnect(self):
        """断开连接"""
        if self.sock:
            try:
                self.sock.close()
            except:
                pass
            self.sock = None
    
    def send_receive(self, data):
        """发送数据并接收响应"""
        try:
            self.sock.send(data)
            return self.sock.recv(4096)
        except socket.timeout:
            return None
        except Exception as e:
            print(f"[!] Send/Receive error: {e}")
            return None
    
    def check_redis_unauth(self):
        """
        Redis未授权访问检测示例
        """
        if not self.connect():
            return None, "Connection failed"
        
        try:
            # 发送INFO命令
            self.sock.send(b"*1\r\n$4\r\ninfo\r\n")
            response = self.sock.recv(4096)
            
            if b"redis_version" in response:
                # 提取版本信息
                version = ""
                for line in response.decode('utf-8', errors='ignore').split('\r\n'):
                    if 'redis_version:' in line:
                        version = line.split(':')[1]
                        break
                
                return True, {
                    "vulnerable": True,
                    "service": "Redis",
                    "version": version,
                    "evidence": "Redis未授权访问"
                }
            elif b"-NOAUTH" in response:
                return False, {"message": "Redis requires authentication"}
            else:
                return False, {"message": "Not a Redis service"}
                
        finally:
            self.disconnect()
    
    def check_mongodb_unauth(self):
        """
        MongoDB未授权访问检测示例
        """
        if not self.connect():
            return None, "Connection failed"
        
        try:
            # MongoDB isMaster请求
            # 构造MongoDB协议消息
            msg = b"\x3d\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00"
            msg += b"\x00\x00\x00\x00\x61\x64\x6d\x69\x6e\x2e\x24\x63\x6d\x64\x00\x00"
            msg += b"\x00\x00\x00\xff\xff\xff\xff\x13\x00\x00\x00\x10\x69\x73\x4d"
            msg += b"\x61\x73\x74\x65\x72\x00\x01\x00\x00\x00\x00"
            
            self.sock.send(msg)
            response = self.sock.recv(4096)
            
            if b"ismaster" in response:
                return True, {
                    "vulnerable": True,
                    "service": "MongoDB",
                    "evidence": "MongoDB未授权访问"
                }
            else:
                return False, {"message": "Not vulnerable or not MongoDB"}
                
        finally:
            self.disconnect()
    
    def check_zookeeper_unauth(self):
        """
        ZooKeeper未授权访问检测示例
        """
        if not self.connect():
            return None, "Connection failed"
        
        try:
            # 发送envi命令
            self.sock.send(b"envi\n")
            response = self.sock.recv(4096)
            
            if b"zookeeper.version" in response:
                return True, {
                    "vulnerable": True,
                    "service": "ZooKeeper",
                    "evidence": "ZooKeeper未授权访问"
                }
            else:
                return False, {"message": "Not vulnerable or not ZooKeeper"}
                
        finally:
            self.disconnect()
    
    def check_memcached_unauth(self):
        """
        Memcached未授权访问检测示例
        """
        if not self.connect():
            return None, "Connection failed"
        
        try:
            # 发送stats命令
            self.sock.send(b"stats\r\n")
            response = self.sock.recv(4096)
            
            if b"STAT pid" in response:
                return True, {
                    "vulnerable": True,
                    "service": "Memcached",
                    "evidence": "Memcached未授权访问"
                }
            else:
                return False, {"message": "Not vulnerable or not Memcached"}
                
        finally:
            self.disconnect()


def main():
    parser = argparse.ArgumentParser(description="Socket协议级POC检测")
    parser.add_argument('-t', '--target', required=True, help='目标IP')
    parser.add_argument('-p', '--port', type=int, required=True, help='目标端口')
    parser.add_argument('--timeout', type=int, default=10, help='超时时间')
    parser.add_argument('--ssl', action='store_true', help='使用SSL')
    parser.add_argument('--service', choices=['redis', 'mongodb', 'zookeeper', 'memcached'],
                        required=True, help='服务类型')
    
    args = parser.parse_args()
    
    poc = SocketPOC(args.target, args.port, args.timeout, args.ssl)
    
    if args.service == 'redis':
        is_vuln, details = poc.check_redis_unauth()
    elif args.service == 'mongodb':
        is_vuln, details = poc.check_mongodb_unauth()
    elif args.service == 'zookeeper':
        is_vuln, details = poc.check_zookeeper_unauth()
    elif args.service == 'memcached':
        is_vuln, details = poc.check_memcached_unauth()
    
    if is_vuln is True:
        print(f"[+] Vulnerable: {details}")
    elif is_vuln is False:
        print(f"[-] Not vulnerable: {details}")
    else:
        print(f"[!] Error: {details}")


if __name__ == '__main__':
    main()
```

---

#### 模板C: Java反序列化POC模板

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Java反序列化漏洞POC检测脚本
支持: WebLogic, JBoss, Jenkins, etc.

Author: [作者]
Date: [日期]
"""

import socket
import struct
import sys
import argparse
import ssl
import base64


class JavaDeserPOC:
    """Java反序列化POC"""
    
    # Java反序列化魔数
    JAVA_MAGIC = b'\xac\xed\x00\x05'
    
    # T3协议Header
    T3_HEADER = b't3 12.2.1\nAS:255\nHL:19\nMS:10000000\nPU:t3://us-l-breens:7001\n\n'
    
    def __init__(self, target, port, timeout=10):
        self.target = target
        self.port = port
        self.timeout = timeout
        self.sock = None
    
    def connect(self):
        """建立连接"""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(self.timeout)
            self.sock.connect((self.target, self.port))
            return True
        except Exception as e:
            print(f"[!] Connection failed: {e}")
            return False
    
    def disconnect(self):
        """断开连接"""
        if self.sock:
            try:
                self.sock.close()
            except:
                pass
            self.sock = None
    
    def build_t3_payload(self, payload_obj):
        """
        构建T3协议Payload
        
        Args:
            payload_obj: 序列化对象字节
        """
        # T3协议消息格式
        # 参考: CVE-2018-2628, CVE-2020-2551
        
        # 构建T3消息头
        header = b'\x00\x00\x09\x73\x65\x72\x76\x65\x72\x00\x00\x00\x1a\x00\x00'
        
        # 构建序列化数据包
        data = self.JAVA_MAGIC + payload_obj
        
        # 添加长度前缀
        length = len(data)
        packet = header + struct.pack('>I', length) + data
        
        return packet
    
    def check_weblogic_t3(self):
        """
        WebLogic T3协议检测
        检测CVE-2018-2628, CVE-2020-2551等
        """
        if not self.connect():
            return None, "Connection failed"
        
        try:
            # 发送T3协议握手
            self.sock.send(self.T3_HEADER)
            response = self.sock.recv(1024)
            
            if b'HELO' in response:
                # T3协议可用，尝试发送恶意序列化数据
                # 这里使用DNSLOG或回显Payload进行检测
                
                # 示例: 使用URLClassLoader加载远程类
                dnslog_domain = "your-dnslog-domain.com"
                
                # 构建检测Payload（简化版）
                # 实际使用时需要完整的Gadget链
                detect_payload = self.build_dnslog_payload(dnslog_domain)
                
                self.sock.send(detect_payload)
                
                # 等待响应
                try:
                    response = self.sock.recv(4096)
                    if b'exception' in response.lower():
                        return True, {
                            "vulnerable": True,
                            "service": "WebLogic T3",
                            "evidence": "T3协议反序列化漏洞可能存在",
                            "note": "请检查DNSLOG确认漏洞"
                        }
                except socket.timeout:
                    pass
                
                return True, {
                    "vulnerable": True,
                    "service": "WebLogic T3",
                    "evidence": "T3协议开放，可能存在反序列化漏洞",
                    "note": "需要进一步验证"
                }
            else:
                return False, {"message": "T3 protocol not available"}
                
        except Exception as e:
            return None, f"Error: {str(e)}"
        finally:
            self.disconnect()
    
    def build_dnslog_payload(self, dnslog_domain):
        """
        构建DNSLOG检测Payload
        实际使用时需要完整的ysoserial Payload
        """
        # 这里只是一个示例框架
        # 实际Payload需要使用ysoserial等工具生成
        
        # 简化示例 - 实际使用时替换为真实Payload
        payload = b'\x77\x04\x66\x6f\x6f\x73\x00\x00\x00\x00'
        return self.build_t3_payload(payload)
    
    def check_jboss_invoker(self):
        """
        JBoss Invoker反序列化检测
        检测CVE-2015-7501, CVE-2017-12149等
        """
        # 实现JBoss检测逻辑
        pass
    
    def check_jenkins_cli(self):
        """
        Jenkins CLI反序列化检测
        检测CVE-2015-8103, CVE-2016-0788等
        """
        # 实现Jenkins检测逻辑
        pass


def generate_ysoserial_payload(gadget, command):
    """
    调用ysoserial生成Payload
    
    Args:
        gadget: Gadget链名称 (如: CommonsCollections1, CommonsBeanutils1)
        command: 要执行的命令
    
    Returns:
        bytes: 序列化Payload
    """
    import subprocess
    
    try:
        result = subprocess.run(
            ['java', '-jar', 'ysoserial.jar', gadget, command],
            capture_output=True,
            timeout=30
        )
        
        if result.returncode == 0:
            return result.stdout
        else:
            print(f"[!] ysoserial error: {result.stderr.decode()}")
            return None
    except Exception as e:
        print(f"[!] Failed to generate payload: {e}")
        return None


def main():
    parser = argparse.ArgumentParser(description="Java反序列化漏洞POC")
    parser.add_argument('-t', '--target', required=True, help='目标IP')
    parser.add_argument('-p', '--port', type=int, default=7001, help='目标端口')
    parser.add_argument('--timeout', type=int, default=10, help='超时时间')
    parser.add_argument('--service', choices=['weblogic', 'jboss', 'jenkins'],
                        default='weblogic', help='目标服务类型')
    parser.add_argument('--gadget', help='ysoserial Gadget链')
    parser.add_argument('--cmd', help='执行命令')
    
    args = parser.parse_args()
    
    poc = JavaDeserPOC(args.target, args.port, args.timeout)
    
    if args.service == 'weblogic':
        is_vuln, details = poc.check_weblogic_t3()
    # elif args.service == 'jboss':
    #     is_vuln, details = poc.check_jboss_invoker()
    # elif args.service == 'jenkins':
    #     is_vuln, details = poc.check_jenkins_cli()
    
    if is_vuln is True:
        print(f"[+] Vulnerable: {details}")
    elif is_vuln is False:
        print(f"[-] Not vulnerable: {details}")
    else:
        print(f"[!] Error: {details}")


if __name__ == '__main__':
    main()
```

---


### 2.2 Nuclei YAML模板

#### 模板A: 通用HTTP漏洞检测模板

```yaml
id: generic-middleware-vuln

info:
  name: Generic Middleware Vulnerability Detection
  author: security-team
  severity: high
  description: |
    这是一个通用的中间件漏洞检测模板。
    检测目标是否存在特定的漏洞特征。
    
    影响版本:
      - Component X < 1.2.3
      - Component Y 2.0.x
    
    利用条件:
      - 目标服务可访问
      - 未启用相关安全补丁
  reference:
    - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-XXXX-XXXXX
    - https://nvd.nist.gov/vuln/detail/CVE-XXXX-XXXXX
    - https://example.com/security-advisory
  classification:
    cvss-metrics: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    cvss-score: 9.8
    cve-id: CVE-XXXX-XXXXX
    cwe-id: CWE-XXX
  metadata:
    verified: true
    max-request: 3
    vendor: vendor-name
    product: product-name
    shodan-query: "product:product-name"
    fofa-query: "app=\"product-name\""
  tags: cve,cve2024,middleware,rce,deserialization

http:
  - method: GET
    path:
      - "{{BaseURL}}/vulnerable/path"
      - "{{BaseURL}}/api/endpoint"
      - "{{BaseURL}}/admin/console"
    
    headers:
      User-Agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
      Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
      Accept-Language: "zh-CN,zh;q=0.9,en;q=0.8"
      Connection: "close"
    
    matchers-condition: and
    matchers:
      # 状态码匹配
      - type: status
        status:
          - 200
          - 500  # 有时漏洞触发会导致500错误
      
      # 关键词匹配
      - type: word
        words:
          - "vulnerable_indicator"
          - "error_message_pattern"
          - "stack_trace_keyword"
        part: body
        condition: or
      
      # 正则匹配
      - type: regex
        regex:
          - "version[\"']?\s*[:=]\s*[\"']?([0-9]+\.[0-9]+\.[0-9]+)"
          - "exception[\"']?\s*[:=]\s*[\"']?([^\"']+)"
        part: body
        condition: or
    
    extractors:
      # 提取版本信息
      - type: regex
        name: version
        group: 1
        regex:
          - "version[\"']?\s*[:=]\s*[\"']?([0-9]+\.[0-9]+\.[0-9]+)"
        part: body
      
      # 提取错误信息
      - type: regex
        name: error
        group: 1
        regex:
          - "error[\"']?\s*[:=]\s*[\"']?([^\"']+)"
        part: body
      
      # 提取整个响应
      - type: dsl
        dsl:
          - "body"
```

---

#### 模板B: POST请求漏洞检测模板

```yaml
id: post-based-vuln

info:
  name: POST-based Vulnerability Detection
  author: security-team
  severity: critical
  description: |
    检测需要POST请求触发的漏洞。
  reference:
    - https://example.com/advisory
  metadata:
    verified: true
    max-request: 2
  tags: rce,post,auth-bypass

http:
  - method: POST
    path:
      - "{{BaseURL}}/api/vulnerable/endpoint"
    
    headers:
      Content-Type: "application/json"
      User-Agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    
    body: |
      {
        "param1": "value1",
        "param2": "{{randstr}}",
        "command": "whoami"
      }
    
    matchers-condition: or
    matchers:
      # 响应内容匹配
      - type: word
        words:
          - "root"
          - "administrator"
          - "nt authority"
        part: body
        condition: or
      
      # 响应时间匹配（时间盲注）
      - type: dsl
        dsl:
          - "duration>=6"
    
    extractors:
      - type: regex
        name: command_output
        group: 0
        regex:
          - "[a-z]+"
        part: body
```

---

#### 模板C: 中间件指纹识别模板

```yaml
id: middleware-fingerprints

info:
  name: Middleware Fingerprint Detection
  author: security-team
  severity: info
  description: |
    检测常见中间件的指纹信息。
  metadata:
    verified: true
    max-request: 1
  tags: fingerprint,middleware,tomcat,weblogic,nginx

http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    
    matchers-condition: or
    matchers:
      # Tomcat指纹
      - type: word
        name: tomcat
        words:
          - "Apache-Coyote"
          - "Tomcat"
          - "JSP/2"
          - "Servlet/"
        part: header
        condition: or
      
      # WebLogic指纹
      - type: word
        name: weblogic
        words:
          - "WebLogic"
          - "WebLogic Server"
          - "bea_wls_internal"
        part: header
        condition: or
      
      # Nginx指纹
      - type: word
        name: nginx
        words:
          - "Server: nginx"
        part: header
        condition: or
      
      # JBoss/WildFly指纹
      - type: word
        name: jboss
        words:
          - "JBoss"
          - "WildFly"
          - "Undertow"
        part: header
        condition: or
      
      # Jetty指纹
      - type: word
        name: jetty
        words:
          - "Server: Jetty"
        part: header
        condition: or
      
      # IIS指纹
      - type: word
        name: iis
        words:
          - "Microsoft-IIS"
          - "X-Powered-By: ASP.NET"
        part: header
        condition: or
    
    extractors:
      - type: regex
        name: server_header
        group: 1
        regex:
          - "Server:\\s*(.+?)(?:\\r|$)"
          - "X-Powered-By:\\s*(.+?)(?:\\r|$)"
        part: header
```

---

#### 模板D: Redis未授权访问检测

```yaml
id: redis-unauthorized-access

info:
  name: Redis Unauthorized Access
  author: security-team
  severity: critical
  description: |
    检测Redis服务是否存在未授权访问漏洞。
    未授权的Redis实例可被攻击者利用进行数据窃取或远程代码执行。
  reference:
    - https://redis.io/topics/security
  metadata:
    verified: true
    max-request: 1
    shodan-query: "port:6379"
  tags: redis,unauth,misconfig

network:
  - inputs:
      - data: "*1\r\n$4\r\ninfo\r\n"
    
    host:
      - "{{Host}}:6379"
    
    matchers-condition: and
    matchers:
      - type: word
        words:
          - "redis_version"
          - "redis_mode"
        condition: or
      
      - type: word
        words:
          - "-NOAUTH"
        negative: true
    
    extractors:
      - type: regex
        name: version
        group: 1
        regex:
          - "redis_version:(.+?)\\r"
      
      - type: regex
        name: os
        group: 1
        regex:
          - "os:(.+?)\\r"
```

---

#### 模板E: MongoDB未授权访问检测

```yaml
id: mongodb-unauthorized-access

info:
  name: MongoDB Unauthorized Access
  author: security-team
  severity: critical
  description: |
    检测MongoDB服务是否存在未授权访问漏洞。
  metadata:
    verified: true
    max-request: 1
    shodan-query: "port:27017"
  tags: mongodb,unauth,misconfig

network:
  - inputs:
      - data: "\x3d\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00\x61\x64\x6d\x69\x6e\x2e\x24\x63\x6d\x64\x00\x00\x00\x00\x00\xff\xff\xff\xff\x13\x00\x00\x00\x10\x69\x73\x4d\x61\x73\x74\x65\x72\x00\x01\x00\x00\x00\x00"
    
    host:
      - "{{Host}}:27017"
    
    matchers:
      - type: word
        words:
          - "ismaster"
          - "maxBsonObjectSize"
        condition: and
    
    extractors:
      - type: regex
        name: version
        group: 1
        regex:
          - "version\"\s*:\s*\"([0-9.]+)"
```

---

#### 模板F: Elasticsearch未授权访问检测

```yaml
id: elasticsearch-unauthorized-access

info:
  name: Elasticsearch Unauthorized Access
  author: security-team
  severity: high
  description: |
    检测Elasticsearch是否存在未授权访问漏洞。
  metadata:
    verified: true
    max-request: 2
    shodan-query: "port:9200"
  tags: elasticsearch,unauth,misconfig

http:
  - method: GET
    path:
      - "{{BaseURL}}/_cluster/health"
      - "{{BaseURL}}/_cat/indices"
    
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      
      - type: word
        words:
          - "cluster_name"
          - "status"
        condition: and
        part: body
    
    extractors:
      - type: regex
        name: cluster_name
        group: 1
        regex:
          - '"cluster_name"\s*:\s*"([^"]+)"'
        part: body
      
      - type: regex
        name: cluster_status
        group: 1
        regex:
          - '"status"\s*:\s*"([^"]+)"'
        part: body
```

---

#### 模板G: Docker API未授权访问检测

```yaml
id: docker-api-unauthorized-access

info:
  name: Docker API Unauthorized Access
  author: security-team
  severity: critical
  description: |
    检测Docker Remote API是否存在未授权访问漏洞。
    未授权的Docker API可被攻击者利用获取宿主机权限。
  reference:
    - https://docs.docker.com/engine/security/protect-access/
  metadata:
    verified: true
    max-request: 1
    shodan-query: "port:2375 docker"
  tags: docker,unauth,api,misconfig

http:
  - method: GET
    path:
      - "{{BaseURL}}/version"
      - "{{BaseURL}}/v1.24/version"
    
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      
      - type: word
        words:
          - "Version"
          - "ApiVersion"
          - "Docker"
        condition: and
        part: body
    
    extractors:
      - type: regex
        name: docker_version
        group: 1
        regex:
          - '"Version"\s*:\s*"([0-9.]+)"'
        part: body
      
      - type: regex
        name: api_version
        group: 1
        regex:
          - '"ApiVersion"\s*:\s*"([0-9.]+)"'
        part: body
```

---

#### 模板H: WebLogic T3协议检测

```yaml
id: weblogic-t3-detect

info:
  name: WebLogic T3 Protocol Detection
  author: security-team
  severity: info
  description: |
    检测WebLogic T3协议是否开放。
    T3协议存在多个反序列化漏洞（CVE-2018-2628, CVE-2020-2551等）。
  reference:
    - https://www.oracle.com/security-alerts/
  metadata:
    verified: true
    max-request: 1
    shodan-query: "port:7001 weblogic"
  tags: weblogic,t3,deserialization,fingerprint

network:
  - inputs:
      - data: "t3 12.2.1\nAS:255\nHL:19\nMS:10000000\n\n"
    
    host:
      - "{{Host}}:7001"
      - "{{Host}}:7002"
    
    matchers:
      - type: word
        words:
          - "HELO"
          - "AS"
          - "HL"
    
    extractors:
      - type: regex
        name: version
        group: 1
        regex:
          - "HELO:(.+?)\\."
```

---

#### 模板I: 多步骤认证绕过检测

```yaml
id: multi-step-auth-bypass

info:
  name: Multi-Step Authentication Bypass
  author: security-team
  severity: high
  description: |
    多步骤请求认证绕过检测模板。
  metadata:
    verified: true
    max-request: 3
  tags: auth-bypass,session-fixation

http:
  # 步骤1: 获取初始会话
  - method: GET
    path:
      - "{{BaseURL}}/login"
    
    extractors:
      - type: regex
        name: csrf_token
        group: 1
        regex:
          - 'name="_csrf" value="([^"]+)"'
        part: body
      
      - type: kval
        name: session_cookie
        kval:
          - "JSESSIONID"
        part: header
    
    # 保存会话信息供后续请求使用
    req-condition: true
  
  # 步骤2: 发送恶意登录请求
  - method: POST
    path:
      - "{{BaseURL}}/login"
    
    headers:
      Content-Type: "application/x-www-form-urlencoded"
      Cookie: "JSESSIONID={{session_cookie}}"
    
    body: |
      username=admin' OR '1'='1&password=anything&_csrf={{csrf_token}}
    
    matchers:
      - type: word
        words:
          - "Welcome"
          - "Dashboard"
          - "admin"
        condition: or
        part: body
      
      - type: status
        status:
          - 302
          - 200
  
  # 步骤3: 访问受保护资源
  - method: GET
    path:
      - "{{BaseURL}}/admin/dashboard"
    
    headers:
      Cookie: "JSESSIONID={{session_cookie}}"
    
    matchers:
      - type: word
        words:
          - "Admin Panel"
          - "User Management"
        condition: or
        part: body
```

---

#### 模板J: 条件竞争检测

```yaml
id: race-condition-test

info:
  name: Race Condition Vulnerability Test
  author: security-team
  severity: medium
  description: |
    条件竞争漏洞检测模板。
  metadata:
    verified: true
    max-request: 10
  tags: race-condition,concurrency

http:
  - method: POST
    path:
      - "{{BaseURL}}/api/transfer"
    
    headers:
      Content-Type: "application/json"
    
    body: |
      {"from": "account1", "to": "account2", "amount": 100}
    
    # 并发发送多个请求
    threads: 10
    
    matchers:
      - type: word
        words:
          - "success"
          - "completed"
        condition: or
        part: body
```

---


## 3. 主机层 - HIDS/EDR检测模板

### 3.1 Sigma规则模板

#### 模板A: 通用Sigma规则结构

```yaml
title: Generic Middleware Attack Detection
id: 12345678-1234-1234-1234-123456789abc
status: experimental
description: |
  检测针对中间件的攻击行为。
  
  检测场景:
  - 异常进程创建
  - 可疑网络连接
  - 敏感文件访问
  
  攻击技术:
  - T1190 - Exploit Public-Facing Application
  - T1059 - Command and Scripting Interpreter
  
references:
  - https://attack.mitre.org/techniques/T1190/
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-XXXX-XXXXX
author: Security Team
date: 2024/01/01
modified: 2024/01/15
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains:
      - 'suspicious_command_1'
      - 'suspicious_command_2'
  condition: selection
falsepositives:
  - 合法管理员操作
  - 自动化部署脚本
level: high
tags:
  - attack.initial_access
  - attack.t1190
  - detection.threat_hunting
```

---

#### 模板B: Java反序列化攻击检测

```yaml
title: Java Deserialization Attack Detection
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: experimental
description: |
  检测Java反序列化攻击行为。
  
  检测指标:
  - ysoserial工具使用
  - 可疑Gadget链加载
  - 异常类加载行为
  
  相关漏洞:
  - CVE-2018-2628 (WebLogic)
  - CVE-2017-12149 (JBoss)
  - CVE-2015-8103 (Jenkins)
references:
  - https://github.com/frohoff/ysoserial
  - https://portswigger.net/web-security/deserialization
author: Security Team
date: 2024/01/01
modified: 2024/01/15
logsource:
  category: process_creation
  product: windows
detection:
  selection_tool:
    CommandLine|contains:
      - 'ysoserial'
      - 'CommonsCollections'
      - 'CommonsBeanutils'
      - 'Jdk7u21'
      - 'JRMPClient'
      - 'JRMPListener'
  
  selection_payload:
    CommandLine|re:
      - 'rO0ABXNy'  # Base64编码的Java序列化数据前缀
      - 'H4sI'      # Base64编码的压缩序列化数据
  
  selection_process:
    ParentImage|endswith:
      - '\java.exe'
      - '\javaw.exe'
    CommandLine|contains:
      - 'ObjectInputStream'
      - 'readObject'
  
  condition: selection_tool or selection_payload or selection_process
falsepositives:
  - 合法的Java应用开发调试
  - 安全测试活动（需授权）
level: critical
tags:
  - attack.execution
  - attack.t1059
  - attack.t1203
  - cve.2018.2628
  - detection.threat_hunting
```

---

#### 模板C: WebLogic进程异常行为检测

```yaml
title: WebLogic Suspicious Process Activity
description: |
  检测WebLogic服务器的异常进程活动，
  可能表明存在成功的漏洞利用。
  
  检测场景:
  - WebLogic进程创建子进程
  - WebLogic执行系统命令
  - WebLogic加载可疑类
  
  相关漏洞:
  - CVE-2020-14882 (Console RCE)
  - CVE-2020-14883 (Console RCE)
  - CVE-2019-2725 (wls9-async RCE)
  - CVE-2018-2628 (T3 Deserialization)
  
references:
  - https://www.oracle.com/security-alerts/
author: Security Team
date: 2024/01/01
logsource:
  category: process_creation
  product: windows
detection:
  selection_parent:
    ParentImage|contains:
      - 'weblogic'
      - 'wlserver'
      - 'bea'
  
  selection_suspicious_child:
    Image|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
      - '\wscript.exe'
      - '\cscript.exe'
      - '\mshta.exe'
      - '\certutil.exe'
      - '\bitsadmin.exe'
      - '\regsvr32.exe'
      - '\rundll32.exe'
  
  selection_suspicious_cmd:
    CommandLine|contains:
      - 'whoami'
      - 'net user'
      - 'net localgroup'
      - 'netstat'
      - 'tasklist'
      - 'systeminfo'
      - 'ipconfig'
      - 'curl'
      - 'wget'
      - 'certutil -urlcache'
      - 'bitsadmin /transfer'
      - 'regsvr32 /s /u /i'
      - 'rundll32'
  
  condition: selection_parent and (selection_suspicious_child or selection_suspicious_cmd)
falsepositives:
  - 合法的WebLogic管理脚本
  - 应用正常功能（如报表生成）
level: high
```

---

#### 模板D: Tomcat异常行为检测

```yaml
title: Tomcat Suspicious Activity Detection
id: b2c3d4e5-f6a7-8901-bcde-f23456789012
status: experimental
description: |
  检测Tomcat服务器的异常活动。
  
  检测场景:
  - 异常WAR文件部署
  - 可疑JSP文件写入
  - 管理后台暴力破解
  
  相关漏洞:
  - CVE-2017-12615 (PUT RCE)
  - CVE-2020-1938 (AJP LFI)
  - CVE-2019-0232 (CGI RCE)
references:
  - https://tomcat.apache.org/security.html
author: Security Team
date: 2024/01/01
logsource:
  category: file_event
  product: windows
detection:
  selection_war_deploy:
    TargetFilename|contains:
      - '\\webapps\\'
      - '/webapps/'
    TargetFilename|endswith:
      - '.war'
      - '.jar'
  
  selection_jsp_write:
    TargetFilename|contains:
      - '\\webapps\\'
      - '/webapps/'
    TargetFilename|endswith:
      - '.jsp'
      - '.jspx'
      - '.jsw'
      - '.jsv'
      - '.jspf'
  
  selection_webshell_indicator:
    TargetFilename|contains:
      - 'shell'
      - 'cmd'
      - 'exec'
      - 'backdoor'
      - 'hack'
  
  condition: (selection_war_deploy or selection_jsp_write) and selection_webshell_indicator
falsepositives:
  - 正常应用部署
  - 开发测试环境
level: high
tags:
  - attack.persistence
  - attack.t1505.003
```

---

#### 模板E: Redis命令执行检测

```yaml
title: Redis Command Execution via Module
id: c3d4e5f6-a7b8-9012-cdef-345678901234
status: experimental
description: |
  检测通过Redis模块加载执行的系统命令。
  
  攻击场景:
  - 攻击者利用Redis未授权访问
  - 加载恶意模块（如redis-rogue-server）
  - 执行任意系统命令
  
  相关技术:
  - T1059 - Command and Scripting Interpreter
  - T1068 - Exploitation for Privilege Escalation
references:
  - https://github.com/n0b0dyCN/redis-rogue-server
author: Security Team
date: 2024/01/01
logsource:
  category: process_creation
  product: linux
detection:
  selection_redis_parent:
    ParentImage|endswith:
      - '/redis-server'
  
  selection_module_load:
    CommandLine|contains:
      - 'MODULE LOAD'
      - 'system.exec'
      - 'system.rev'
  
  selection_suspicious_child:
    Image|endswith:
      - '/bin/sh'
      - '/bin/bash'
      - '/usr/bin/python'
      - '/usr/bin/perl'
      - '/usr/bin/ruby'
      - '/usr/bin/curl'
      - '/usr/bin/wget'
      - 'nc'
      - 'netcat'
  
  condition: selection_redis_parent and selection_suspicious_child
falsepositives:
  - Redis合法备份脚本
  - 监控代理程序
level: critical
tags:
  - attack.execution
  - attack.t1059
  - attack.t1068
```

---

#### 模板F: Docker容器逃逸检测

```yaml
title: Docker Container Escape Detection
id: d4e5f6a7-b8c9-0123-defa-456789012345
status: experimental
description: |
  检测Docker容器逃逸行为。
  
  逃逸技术:
  - 特权容器逃逸
  - Docker Socket挂载逃逸
  - procfs逃逸
  - Dirty Cow等内核漏洞
  
  检测指标:
  - 容器内访问宿主机/proc
  - 容器内挂载宿主机文件系统
  - 容器内创建新容器
references:
  - https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-breakout
author: Security Team
date: 2024/01/01
logsource:
  category: process_creation
  product: linux
detection:
  selection_privileged_access:
    CommandLine|contains:
      - '/proc/1/root'
      - '/proc/1/cgroup'
      - '/host/proc'
      - '/host/sys'
  
  selection_mount_escape:
    CommandLine|contains:
      - 'mount /dev/sd'
      - 'mount -o bind /host'
      - 'chroot /mnt'
  
  selection_docker_socket:
    CommandLine|contains:
      - '-v /var/run/docker.sock'
      - '-v /run/docker.sock'
      - 'docker.sock'
      - 'docker -H unix:///var/run/docker.sock'
  
  selection_new_container:
    CommandLine|contains|all:
      - 'docker run'
      - '--privileged'
      - '-v /:'
  
  selection_cgroup_escape:
    CommandLine|contains|all:
      - 'mkdir /tmp/cgrp'
      - 'mount -t cgroup'
      - 'release_agent'
  
  condition: selection_privileged_access or selection_mount_escape or selection_docker_socket or selection_new_container or selection_cgroup_escape
falsepositives:
  - 合法的Docker管理操作
  - CI/CD流水线
level: critical
tags:
  - attack.privilege_escalation
  - attack.t1611
```

---

#### 模板G: 中间件配置文件篡改检测

```yaml
title: Middleware Configuration File Tampering
id: e5f6a7b8-c9d0-1234-efab-567890123456
status: experimental
description: |
  检测中间件配置文件的异常修改。
  
  检测场景:
  - web.xml异常修改
  - server.xml异常修改
  - 新增可疑Valve/Filter
  - 修改安全相关配置
references:
  - https://attack.mitre.org/techniques/T1505/003/
author: Security Team
date: 2024/01/01
logsource:
  category: file_change
  product: windows
detection:
  selection_config_files:
    TargetFilename|endswith:
      - '\\web.xml'
      - '\\server.xml'
      - '\\context.xml'
      - '\\weblogic.xml'
      - '\\config.xml'
      - '\\nginx.conf'
      - '\\httpd.conf'
  
  selection_suspicious_changes:
    - CommandLine|contains:
        - '<Valve'
        - '<Filter'
        - '<Listener'
        - 'className='
        - 'org.apache.catalina.valves'
        - 'webshell'
        - 'cmd.jsp'
    - CommandLine|contains:
        - 'readonly="false"'
        - 'privileged="true"'
        - 'allowLinking="true"'
        - 'debug="99"'
  
  condition: selection_config_files and selection_suspicious_changes
falsepositives:
  - 合法的配置更新
  - 应用升级
level: high
tags:
  - attack.persistence
  - attack.t1505.003
```

---

#### 模板H: 内存马检测（Java Agent注入）

```yaml
title: Java Agent Injection Detection
id: f6a7b8c9-d0e1-2345-fabc-678901234567
status: experimental
description: |
  检测Java Agent注入行为，可能表明内存马注入。
  
  攻击技术:
  - Instrumentation API滥用
  - Java Agent动态加载
  - 类字节码修改
  
  相关工具:
  - retransformClasses
  - redefineClasses
  - attach API
references:
  - https://github.com/alibaba/arthas
  - https://docs.oracle.com/javase/8/docs/api/java/lang/instrument/Instrumentation.html
author: Security Team
date: 2024/01/01
logsource:
  category: process_creation
  product: windows
detection:
  selection_java_agent:
    CommandLine|contains:
      - '-javaagent:'
      - 'Premain-Class'
      - 'Agent-Class'
      - 'instrument'
      - 'retransformClasses'
      - 'redefineClasses'
  
  selection_attach_api:
    CommandLine|contains:
      - 'com.sun.tools.attach'
      - 'VirtualMachine.attach'
      - 'loadAgent'
  
  selection_suspicious_jar:
    CommandLine|contains:
      - 'agent.jar'
      - 'memshell.jar'
      - 'webshell-agent.jar'
      - 'shell.jar'
  
  condition: selection_java_agent or selection_attach_api or selection_suspicious_jar
falsepositives:
  - 合法的APM工具（如SkyWalking, Pinpoint）
  - 性能监控工具
level: high
tags:
  - attack.defense_evasion
  - attack.t1055
```

---

#### 模板I: 网络连接异常检测

```yaml
title: Suspicious Network Connection from Middleware
id: a7b8c9d0-e1f2-3456-abcd-789012345678
status: experimental
description: |
  检测中间件进程的可疑网络连接。
  
  检测场景:
  - 中间件进程连接C2服务器
  - 中间件进程发起反向Shell
  - 异常端口通信
references:
  - https://attack.mitre.org/techniques/T1071/
author: Security Team
date: 2024/01/01
logsource:
  category: network_connection
  product: windows
detection:
  selection_middleware_process:
    Image|contains:
      - 'java.exe'
      - 'tomcat'
      - 'weblogic'
      - 'nginx'
      - 'httpd'
      - 'redis-server'
      - 'mongod'
      - 'elasticsearch'
  
  selection_suspicious_destination:
    DestinationPort:
      - 4444    # Metasploit默认
      - 5555    # ADB默认
      - 6666    # 常见后门端口
      - 7777
      - 8888
      - 9999
      - 12345   # NetBus
      - 31337   # Back Orifice
      - 54321   # SchoolBus
  
  selection_suspicious_ip:
    DestinationIp|contains:
      - '192.168.'   # 内网（可能是横向移动）
      - '10.'
      - '172.16.'
      - '172.17.'
      - '172.18.'
      - '172.19.'
      - '172.20.'
      - '172.21.'
      - '172.22.'
      - '172.23.'
      - '172.24.'
      - '172.25.'
      - '172.26.'
      - '172.27.'
      - '172.28.'
      - '172.29.'
      - '172.30.'
      - '172.31.'
  
  filter_legitimate:
    DestinationPort:
      - 80
      - 443
      - 3306    # MySQL
      - 5432    # PostgreSQL
      - 6379    # Redis
      - 9200    # Elasticsearch
      - 27017   # MongoDB
  
  condition: selection_middleware_process and (selection_suspicious_destination or selection_suspicious_ip) and not filter_legitimate
falsepositives:
  - 合法的微服务通信
  - 数据库连接池
level: medium
tags:
  - attack.command_and_control
  - attack.t1071
```

---


### 3.2 Yara规则模板

#### 模板A: Java反序列化Payload检测

```yara
rule Java_Serialized_Object
{
    meta:
        description = "Detects Java serialized objects"
        author = "Security Team"
        reference = "https://docs.oracle.com/javase/8/docs/platform/serialization/spec/protocol.html"
        date = "2024-01-01"
        hash = "N/A"
        severity = "medium"
        confidence = "high"
    
    strings:
        // Java序列化魔数 (0xACED0005)
        $magic = { AC ED 00 05 }
        
        // 常见类签名
        $class_annotation = { 73 72 00 }  // TC_OBJECT + TC_CLASSDESC + classNameLength
        $class_proxy = { 73 7D 00 }       // TC_OBJECT + TC_PROXYCLASSDESC
        
        // 常见Gadget链类名
        $cc1 = "org.apache.commons.collections.functors.InvokerTransformer"
        $cc2 = "org.apache.commons.collections.functors.InstantiateTransformer"
        $cc3 = "org.apache.commons.collections.functors.ChainedTransformer"
        $cc4 = "org.apache.commons.collections.map.LazyMap"
        
        // CommonsCollections3/4
        $cc3_1 = "org.apache.commons.collections4.functors.InvokerTransformer"
        $cc3_2 = "org.apache.commons.collections4.functors.InstantiateTransformer"
        
        // CommonsBeanutils
        $cb1 = "org.apache.commons.beanutils.BeanComparator"
        
        // Jdk7u21
        $jdk7 = "java.util.PriorityQueue"
        $jdk7_2 = "com.sun.rowset.JdbcRowSetImpl"
        
        // ROME
        $rome1 = "com.sun.syndication.feed.impl.ToStringBean"
        $rome2 = "com.sun.syndication.feed.impl.EqualsBean"
        
        // Hibernate
        $hibernate = "org.hibernate.property.BasicPropertyAccessor"
        
        // Spring
        $spring1 = "org.springframework.beans.factory.ObjectFactory"
        $spring2 = "org.springframework.core.SerializableTypeWrapper"
        
        // JSON相关
        $json1 = "net.sf.json.JSONObject"
        $json2 = "com.alibaba.fastjson.JSONObject"
    
    condition:
        $magic at 0 and
        (
            any of ($cc*) or
            any of ($cb*) or
            any of ($jdk7*) or
            any of ($rome*) or
            $hibernate or
            any of ($spring*) or
            any of ($json*)
        )
}

rule Java_Deserialization_Exploit_Payload
{
    meta:
        description = "Detects Java deserialization exploit payloads"
        author = "Security Team"
        reference = "https://github.com/frohoff/ysoserial"
        date = "2024-01-01"
        severity = "critical"
        confidence = "high"
    
    strings:
        // Java序列化魔数
        $magic = { AC ED 00 05 }
        
        // ysoserial生成的Payload特征
        $ysoserial_marker = "ysoserial" nocase
        
        // 常见命令执行特征
        $exec1 = "Runtime.getRuntime().exec"
        $exec2 = "ProcessBuilder"
        $exec3 = "java/lang/Runtime"
        $exec4 = "java/lang/ProcessBuilder"
        
        // 反射调用特征
        $reflect1 = "java/lang/reflect/Method"
        $reflect2 = "setAccessible"
        $reflect3 = "invoke"
        
        // URLClassLoader加载远程类
        $urlclassloader = "java/net/URLClassLoader"
        $defineclass = "defineClass"
        
        // JNDI注入特征
        $jndi1 = "javax/naming/InitialContext"
        $jndi2 = "ldap://"
        $jndi3 = "rmi://"
        $jndi4 = "dns://"
        $jndi5 = "corbaname:"
    
    condition:
        $magic at 0 and
        (
            $ysoserial_marker or
            (2 of ($exec*)) or
            (all of ($reflect*)) or
            ($urlclassloader and $defineclass) or
            ($jndi1 and any of ($jndi2, $jndi3, $jndi4, $jndi5))
        )
}

rule Java_RMI_Malicious_Payload
{
    meta:
        description = "Detects malicious Java RMI payloads"
        author = "Security Team"
        reference = "https://docs.oracle.com/javase/8/docs/platform/rmi/spec/rmiTOC.html"
        date = "2024-01-01"
        severity = "high"
    
    strings:
        // RMI协议魔数
        $rmi_magic = { 4A 52 4D 49 }  // "JRMI"
        
        // RMI调用特征
        $rmi_call = { 50 61 73 73 }   // "Pass"
        $rmi_return = { 52 65 74 75 } // "Retu"
        
        // 常见RMI攻击Payload
        $jrmp_listener = "JRMPListener"
        $jrmp_client = "JRMPClient"
        
        // 远程类加载
        $remote_class = "java.rmi.server.codebase"
        
        // JMX RMI特征
        $jmx_rmi = "jmxrmi"
        $jmx_connector = "JMXConnector"
    
    condition:
        $rmi_magic and
        (
            any of ($jrmp*) or
            $remote_class or
            any of ($jmx*)
        )
}
```

---

#### 模板B: WebShell检测规则

```yara
rule JSP_WebShell_Generic
{
    meta:
        description = "Detects generic JSP webshells"
        author = "Security Team"
        date = "2024-01-01"
        severity = "critical"
    
    strings:
        // JSP标签
        $jsp1 = "<%@page"
        $jsp2 = "<%@ page"
        $jsp3 = "<%!"
        $jsp4 = "<%="
        
        // 命令执行
        $cmd1 = "Runtime.getRuntime()"
        $cmd2 = "exec("
        $cmd3 = "ProcessBuilder"
        $cmd4 = "getInputStream()"
        
        // 反射
        $reflect1 = "Class.forName"
        $reflect2 = "getMethod"
        $reflect3 = "invoke"
        
        // 危险函数
        $danger1 = "request.getParameter"
        $danger2 = "new java.io.File"
        $danger3 = "FileOutputStream"
        $danger4 = "FileInputStream"
        
        // 常见webshell特征
        $shell1 = "cmd" nocase
        $shell2 = "command" nocase
        $shell3 = "shell" nocase
        $shell4 = "exec" nocase
        $shell5 = "execute" nocase
        $shell6 = "password" nocase
        $shell7 = "pass" nocase
        
        // 编码绕过
        $encode1 = "base64"
        $encode2 = "URLDecoder"
        $encode3 = "decode"
        $encode4 = "new String("
    
    condition:
        any of ($jsp*) and
        (
            ($cmd1 and $cmd2) or
            ($cmd3 and $cmd4) or
            (all of ($reflect*)) or
            (2 of ($danger*))
        ) and
        (2 of ($shell*)) and
        filesize < 100KB
}

rule JSP_WebShell_China_Chopper
{
    meta:
        description = "Detects China Chopper JSP webshell"
        author = "Security Team"
        reference = "https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/rpt-china-chopper.pdf"
        date = "2024-01-01"
        severity = "critical"
    
    strings:
        $chopper1 = "request.getInputStream()"
        $chopper2 = "new java.io.ByteArrayOutputStream()"
        $chopper3 = "session.putValue"
        $chopper4 = "pageContext.getOutputStream()"
        
        // 中国菜刀特征密码字段
        $pass1 = { 70 61 73 73 77 6F 72 64 }  // "password"
        
        // 常见变体
        $variant1 = "if(request.getMethod()==\"POST\")"
        $variant2 = "java.io.InputStream in = Runtime.getRuntime()"
    
    condition:
        3 of ($chopper*) or
        (2 of ($chopper*) and any of ($variant*))
}

rule JSP_WebShell_Behinder
{
    meta:
        description = "Detects Behinder JSP webshell"
        author = "Security Team"
        reference = "https://github.com/rebeyond/Behinder"
        date = "2024-01-01"
        severity = "critical"
    
    strings:
        // 冰蝎特征
        $behinder1 = "javax.crypto.Cipher"
        $behinder2 = "SecretKeySpec"
        $behinder3 = "AES/ECB/PKCS5Padding"
        $behinder4 = "doFinal"
        
        // 密钥协商特征
        $key1 = "session.getAttribute"
        $key2 = "session.setAttribute"
        
        // 类加载特征
        $loader1 = "defineClass"
        $loader2 = "ClassLoader"
    
    condition:
        all of ($behinder*) and
        any of ($key*) and
        any of ($loader*)
}

rule JSP_WebShell_Godzilla
{
    meta:
        description = "Detects Godzilla JSP webshell"
        author = "Security Team"
        reference = "https://github.com/BeichenDream/Godzilla"
        date = "2024-01-01"
        severity = "critical"
    
    strings:
        // 哥斯拉特征
        $godzilla1 = "javax.crypto.spec.SecretKeySpec"
        $godzilla2 = "javax.crypto.Cipher"
        $godzilla3 = "AES/CBC/PKCS5Padding"
        $godzilla4 = "IvParameterSpec"
        
        // 密钥特征
        $key1 = "3c6e0b8a9c15224a"
        $key2 = "e45e329feb5d925b"
        
        // 类加载器
        $loader1 = "java.net.URLClassLoader"
        $loader2 = "java.security.SecureClassLoader"
    
    condition:
        3 of ($godzilla*) or
        any of ($key*) or
        (all of ($loader*) and 2 of ($godzilla*))
}

rule PHP_WebShell_Generic
{
    meta:
        description = "Detects generic PHP webshells"
        author = "Security Team"
        date = "2024-01-01"
        severity = "critical"
    
    strings:
        // PHP标签
        $php1 = "<?php"
        $php2 = "<?="
        $php3 = "<? "
        
        // 危险函数
        $danger1 = "eval("
        $danger2 = "assert("
        $danger3 = "system("
        $danger4 = "exec("
        $danger5 = "shell_exec("
        $danger6 = "passthru("
        $danger7 = "popen("
        $danger8 = "proc_open("
        $danger9 = "pcntl_exec("
        
        // 文件操作
        $file1 = "file_get_contents"
        $file2 = "file_put_contents"
        $file3 = "fopen"
        $file4 = "fwrite"
        
        // 编码绕过
        $encode1 = "base64_decode"
        $encode2 = "str_rot13"
        $encode3 = "gzinflate"
        $encode4 = "gzuncompress"
        
        // 常见webshell特征
        $shell1 = "$_POST["
        $shell2 = "$_GET["
        $shell3 = "$_REQUEST["
        $shell4 = "password"
        $shell5 = "cmd"
        $shell6 = "command"
    
    condition:
        any of ($php*) and
        (2 of ($danger*)) and
        (any of ($shell*)) and
        filesize < 100KB
}
```

---

#### 模板C: 内存马检测规则

```yara
rule Java_Memory_Shell_Agent
{
    meta:
        description = "Detects Java memory shell agents"
        author = "Security Team"
        date = "2024-01-01"
        severity = "critical"
    
    strings:
        // Agent特征
        $agent1 = "Premain-Class"
        $agent2 = "Agent-Class"
        $agent3 = "Can-Redefine-Classes"
        $agent4 = "Can-Retransform-Classes"
        
        // Instrumentation
        $inst1 = "java/lang/instrument/Instrumentation"
        $inst2 = "retransformClasses"
        $inst3 = "redefineClasses"
        $inst4 = "addTransformer"
        
        // 字节码操作
        $bytecode1 = "javassist"
        $bytecode2 = "asm"
        $bytecode3 = "cglib"
        $bytecode4 = "ByteBuddy"
        
        // 类修改特征
        $modify1 = "doFilter"
        $modify2 = "service"
        $modify3 = "_jspService"
        $modify4 = "Valve"
    
    condition:
        (2 of ($agent*) or $inst1) and
        (any of ($inst*) or any of ($bytecode*)) and
        any of ($modify*)
}

rule Java_Filter_Webshell
{
    meta:
        description = "Detects Java Filter-based webshells"
        author = "Security Team"
        date = "2024-01-01"
        severity = "critical"
    
    strings:
        // Filter接口实现
        $filter1 = "javax/servlet/Filter"
        $filter2 = "doFilter(Ljavax/servlet/ServletRequest;Ljavax/servlet/ServletResponse;Ljavax/servlet/FilterChain;)V"
        
        // 动态注册Filter
        $register1 = "addFilter"
        $register2 = "FilterRegistration"
        $register3 = "ServletContext"
        
        // 命令执行
        $exec1 = "java/lang/Runtime"
        $exec2 = "getRuntime"
        $exec3 = "exec"
        
        // 常见webshell特征
        $shell1 = "cmd"
        $shell2 = "command"
        $shell3 = "exec"
        $shell4 = "x"
        $shell5 = "pass"
    
    condition:
        $filter1 and
        any of ($register*) and
        (all of ($exec*)) and
        any of ($shell*)
}

rule Java_Servlet_Webshell
{
    meta:
        description = "Detects Java Servlet-based webshells"
        author = "Security Team"
        date = "2024-01-01"
        severity = "critical"
    
    strings:
        // Servlet接口
        $servlet1 = "javax/servlet/http/HttpServlet"
        $servlet2 = "service(Ljavax/servlet/ServletRequest;Ljavax/servlet/ServletResponse;)V"
        $servlet3 = "doGet"
        $servlet4 = "doPost"
        
        // 动态注册
        $register1 = "addServlet"
        $register2 = "ServletRegistration"
        
        // 命令执行
        $exec1 = "java/lang/Runtime"
        $exec2 = "getRuntime"
        $exec3 = "exec"
        $exec4 = "ProcessBuilder"
    
    condition:
        any of ($servlet*) and
        any of ($register*) and
        (all of ($exec*) or $exec4)
}

rule Java_Listener_Webshell
{
    meta:
        description = "Detects Java Listener-based webshells"
        author = "Security Team"
        date = "2024-01-01"
        severity = "critical"
    
    strings:
        // Listener接口
        $listener1 = "javax/servlet/ServletRequestListener"
        $listener2 = "requestInitialized"
        $listener3 = "requestDestroyed"
        
        // 动态注册
        $register1 = "addListener"
        
        // 命令执行
        $exec1 = "java/lang/Runtime"
        $exec2 = "exec"
        
        // 反射特征
        $reflect1 = "java/lang/reflect/Method"
        $reflect2 = "invoke"
    
    condition:
        $listener1 and
        any of ($register*) and
        (all of ($exec*) or all of ($reflect*))
}
```

---

#### 模板D: Exploit JAR/WAR包检测

```yara
rule Exploit_JAR_Generic
{
    meta:
        description = "Detects potentially malicious JAR files"
        author = "Security Team"
        date = "2024-01-01"
        severity = "high"
    
    strings:
        // JAR文件魔数 (ZIP格式)
        $jar_magic = { 50 4B 03 04 }
        
        // MANIFEST.MF特征
        $manifest1 = "META-INF/MANIFEST.MF"
        $manifest2 = "Main-Class:"
        
        // 可疑的Main-Class
        $suspicious_main1 = "Exploit"
        $suspicious_main2 = "Payload"
        $suspicious_main3 = "Shell"
        $suspicious_main4 = "RCE"
        
        // 危险类
        $danger_class1 = "Runtime"
        $danger_class2 = "ProcessBuilder"
        $danger_class3 = "URLClassLoader"
        $danger_class4 = "defineClass"
    
    condition:
        $jar_magic at 0 and
        any of ($manifest*) and
        (any of ($suspicious_main*) or any of ($danger_class*))
}

rule Exploit_WAR_Generic
{
    meta:
        description = "Detects potentially malicious WAR files"
        author = "Security Team"
        date = "2024-01-01"
        severity = "high"
    
    strings:
        // WAR文件魔数
        $war_magic = { 50 4B 03 04 }
        
        // WAR结构特征
        $webinf = "WEB-INF/"
        $webxml = "WEB-INF/web.xml"
        $classes = "WEB-INF/classes/"
        $lib = "WEB-INF/lib/"
        
        // 可疑JSP
        $jsp1 = ".jsp"
        $jsp2 = ".jspx"
        
        // webshell特征文件名
        $shell_name1 = "shell"
        $shell_name2 = "cmd"
        $shell_name3 = "exec"
        $shell_name4 = "backdoor"
        $shell_name5 = "hack"
    
    condition:
        $war_magic at 0 and
        $webinf and
        (
            any of ($jsp*) and
            any of ($shell_name*)
        )
}

rule ysoserial_JAR
{
    meta:
        description = "Detects ysoserial JAR files"
        author = "Security Team"
        reference = "https://github.com/frohoff/ysoserial"
        date = "2024-01-01"
        severity = "high"
    
    strings:
        $ysoserial1 = "ysoserial"
        $ysoserial2 = "ysoserial.GeneratePayload"
        $ysoserial3 = "ysoserial.payloads"
        
        // Gadget链类
        $gadget1 = "CommonsCollections"
        $gadget2 = "CommonsBeanutils"
        $gadget3 = "Jdk7u21"
        $gadget4 = "Spring1"
        $gadget5 = "Hibernate1"
        $gadget6 = "ROME"
    
    condition:
        any of ($ysoserial*) or
        (2 of ($gadget*))
}
```

---


### 3.3 Auditd/Systemmon配置

#### 模板A: Linux Auditd规则配置

```bash
# ============================================
# Linux Auditd 中间件安全监控规则
# 用途: 监控中间件相关的安全事件
# 部署: 将规则添加到 /etc/audit/rules.d/ 目录
# ============================================

# 删除所有现有规则
-D

# 设置缓冲区大小
-b 8192

# 设置失败模式 (0=silent, 1=printk, 2=panic)
-f 1

# ============================================
# 1. Tomcat 监控规则
# ============================================

# 监控Tomcat配置文件修改
-w /etc/tomcat/ -p wa -k tomcat_config_change
-w /var/lib/tomcat/ -p wa -k tomcat_file_change
-w /opt/tomcat/ -p wa -k tomcat_file_change
-w /usr/share/tomcat/ -p wa -k tomcat_file_change

# 监控webapps目录（WAR/JSP部署）
-w /var/lib/tomcat/webapps/ -p wa -k tomcat_webapp_deploy
-w /opt/tomcat/webapps/ -p wa -k tomcat_webapp_deploy

# 监控conf目录（配置文件）
-w /var/lib/tomcat/conf/ -p wa -k tomcat_conf_change
-w /var/lib/tomcat/conf/server.xml -p wa -k tomcat_server_xml
-w /var/lib/tomcat/conf/web.xml -p wa -k tomcat_web_xml
-w /var/lib/tomcat/conf/tomcat-users.xml -p wa -k tomcat_users_xml

# 监控日志目录
-w /var/log/tomcat/ -p wa -k tomcat_logs

# ============================================
# 2. WebLogic 监控规则
# ============================================

# 监控WebLogic安装目录
-w /opt/oracle/Middleware/ -p wa -k weblogic_file_change
-w /home/oracle/Oracle/Middleware/ -p wa -k weblogic_file_change
-w /u01/app/oracle/Middleware/ -p wa -k weblogic_file_change

# 监控domain配置
-w /opt/oracle/Middleware/user_projects/domains/ -p wa -k weblogic_domain_change
-w /opt/oracle/Middleware/wlserver/ -p wa -k weblogic_server_change

# 监控config.xml
-w /opt/oracle/Middleware/user_projects/domains/*/config/config.xml -p wa -k weblogic_config_xml

# 监控autodeploy目录
-w /opt/oracle/Middleware/user_projects/domains/*/autodeploy/ -p wa -k weblogic_autodeploy

# ============================================
# 3. Nginx 监控规则
# ============================================

# 监控Nginx配置文件
-w /etc/nginx/ -p wa -k nginx_config_change
-w /etc/nginx/nginx.conf -p wa -k nginx_main_conf
-w /etc/nginx/conf.d/ -p wa -k nginx_conf_d
-w /usr/local/nginx/conf/ -p wa -k nginx_conf

# 监控HTML目录
-w /var/www/html/ -p wa -k nginx_webroot_change
-w /usr/share/nginx/html/ -p wa -k nginx_webroot_change

# 监控日志
-w /var/log/nginx/ -p wa -k nginx_logs

# ============================================
# 4. Apache HTTPD 监控规则
# ============================================

# 监控Apache配置
-w /etc/httpd/ -p wa -k httpd_config_change
-w /etc/apache2/ -p wa -k apache2_config_change
-w /etc/httpd/conf/httpd.conf -p wa -k httpd_main_conf
-w /etc/apache2/apache2.conf -p wa -k apache2_main_conf

# 监控web根目录
-w /var/www/html/ -p wa -k httpd_webroot_change
-w /var/www/cgi-bin/ -p wa -k httpd_cgi_change

# 监控htaccess文件
-w /var/www/html/.htaccess -p wa -k httpd_htaccess
-a always,exit -F arch=b64 -S open -F dir=/var/www -F name=.htaccess -k httpd_htaccess_create

# ============================================
# 5. Redis 监控规则
# ============================================

# 监控Redis配置文件
-w /etc/redis/ -p wa -k redis_config_change
-w /etc/redis/redis.conf -p wa -k redis_conf
-w /etc/redis/*.conf -p wa -k redis_conf_files

# 监控数据目录
-w /var/lib/redis/ -p wa -k redis_data_change
-w /var/lib/redis/dump.rdb -p wa -k redis_dump

# 监控Redis进程执行
-a always,exit -F arch=b64 -S execve -C uid!=redis -F exe=/usr/bin/redis-server -k redis_unauthorized_exec

# ============================================
# 6. MongoDB 监控规则
# ============================================

# 监控MongoDB配置
-w /etc/mongod.conf -p wa -k mongodb_config_change
-w /etc/mongodb.conf -p wa -k mongodb_config_change

# 监控数据目录
-w /var/lib/mongodb/ -p wa -k mongodb_data_change
-w /data/db/ -p wa -k mongodb_data_change

# ============================================
# 7. Elasticsearch 监控规则
# ============================================

# 监控ES配置
-w /etc/elasticsearch/ -p wa -k elasticsearch_config_change
-w /etc/elasticsearch/elasticsearch.yml -p wa -k elasticsearch_yml

# 监控数据目录
-w /var/lib/elasticsearch/ -p wa -k elasticsearch_data_change

# ============================================
# 8. Docker 监控规则
# ============================================

# 监控Docker配置
-w /etc/docker/ -p wa -k docker_config_change
-w /etc/docker/daemon.json -p wa -k docker_daemon_json

# 监控Docker Socket
-w /var/run/docker.sock -p wa -k docker_socket_access

# 监控Docker命令执行
-a always,exit -F arch=b64 -S execve -F exe=/usr/bin/docker -k docker_command
-a always,exit -F arch=b64 -S execve -F exe=/usr/bin/dockerd -k docker_daemon

# 监控特权容器创建
-a always,exit -F arch=b64 -S execve -F exe=/usr/bin/docker -F a0=docker -F a1=run --privileged -k docker_privileged_container

# ============================================
# 9. Java 进程监控
# ============================================

# 监控Java进程执行
-a always,exit -F arch=b64 -S execve -F exe=/usr/bin/java -k java_execution
-a always,exit -F arch=b64 -S execve -F exe=/usr/lib/jvm/*/bin/java -k java_execution

# 监控javaagent参数使用
-a always,exit -F arch=b64 -S execve -F exe=/usr/bin/java -F a0=-javaagent -k java_agent_injection

# 监控JAR文件执行
-a always,exit -F arch=b64 -S execve -F exe=/usr/bin/java -F a0=-jar -k java_jar_execution

# ============================================
# 10. 通用安全监控规则
# ============================================

# 监控/etc/passwd修改
-w /etc/passwd -p wa -k passwd_change
-w /etc/shadow -p wa -k shadow_change
-w /etc/group -p wa -k group_change
-w /etc/sudoers -p wa -k sudoers_change
-w /etc/sudoers.d/ -p wa -k sudoers_d_change

# 监控SSH配置
-w /etc/ssh/sshd_config -p wa -k sshd_config_change
-w /root/.ssh/ -p wa -k root_ssh_key_change
-w /home/*/.ssh/ -p wa -k user_ssh_key_change

# 监控crontab
-w /etc/crontab -p wa -k crontab_change
-w /etc/cron.d/ -p wa -k cron_d_change
-w /etc/cron.daily/ -p wa -k cron_daily_change
-w /etc/cron.hourly/ -p wa -k cron_hourly_change
-w /var/spool/cron/ -p wa -k user_cron_change

# 监控systemd服务
-w /etc/systemd/system/ -p wa -k systemd_service_change
-w /usr/lib/systemd/system/ -p wa -k systemd_lib_change
-w /lib/systemd/system/ -p wa -k systemd_lib_change

# 监控PAM配置
-w /etc/pam.d/ -p wa -k pam_config_change
-w /etc/security/ -p wa -k security_config_change

# 监控内核模块
-w /sbin/insmod -p x -k kernel_module_load
-w /sbin/rmmod -p x -k kernel_module_remove
-w /sbin/modprobe -p x -k kernel_module_probe

# 监控SELinux/AppArmor
-w /etc/selinux/ -p wa -k selinux_config_change
-w /etc/apparmor/ -p wa -k apparmor_config_change
-w /etc/apparmor.d/ -p wa -k apparmor_profile_change

# ============================================
# 11. 可疑行为监控
# ============================================

# 监控SUID/SGID文件修改
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -k permission_modification

# 监控文件属性修改（immutable等）
-a always,exit -F arch=b64 -S chattr -k file_attr_change

# 监控ptrace系统调用（进程注入）
-a always,exit -F arch=b64 -S ptrace -k process_injection

# 监控进程间内存操作
-a always,exit -F arch=b64 -S process_vm_writev -k process_memory_write

# 监控加载内核模块
-a always,exit -F arch=b64 -S init_module -S finit_module -k kernel_module_load

# ============================================
# 12. 网络相关监控
# ============================================

# 监控防火墙规则修改
-w /sbin/iptables -p x -k iptables_change
-w /sbin/ip6tables -p x -k ip6tables_change
-w /sbin/firewalld -p x -k firewalld_change
-w /etc/sysconfig/iptables -p wa -k iptables_config

# 监控网络配置
-w /etc/sysconfig/network-scripts/ -p wa -k network_config_change
-w /etc/network/ -p wa -k network_config_change

# ============================================
# 持久化规则
# ============================================

# 使规则持久化
e 1
```

---

#### 模板B: Windows Sysmon配置

```xml
<!-- ============================================
     Windows Sysmon 中间件安全监控配置
     用途: 监控中间件相关的安全事件
     部署: sysmon -i sysmon-middleware-config.xml
     ============================================ -->

<Sysmon schemaversion="4.90">
  
  <!-- 哈希算法 -->
  <HashAlgorithms>md5,sha256,IMPHASH</HashAlgorithms>
  
  <!-- 事件过滤 -->
  <EventFiltering>
    
    <!-- ============================================
         1. 进程创建监控 (Event ID 1)
         ============================================ -->
    <RuleGroup name="Process Creation" groupRelation="or">
      <ProcessCreate onmatch="include">
        <!-- Tomcat相关进程 -->
        <ParentImage condition="contains">tomcat</ParentImage>
        <Image condition="contains">tomcat</Image>
        <CommandLine condition="contains">tomcat</CommandLine>
        
        <!-- WebLogic相关进程 -->
        <ParentImage condition="contains">weblogic</ParentImage>
        <Image condition="contains">weblogic</Image>
        <CommandLine condition="contains">weblogic</CommandLine>
        <CommandLine condition="contains">wlserver</CommandLine>
        
        <!-- Java进程监控 -->
        <Image condition="end with">java.exe</Image>
        <Image condition="end with">javaw.exe</Image>
        
        <!-- 可疑Java参数 -->
        <CommandLine condition="contains">-javaagent:</CommandLine>
        <CommandLine condition="contains">javaagent</CommandLine>
        <CommandLine condition="contains">Premain-Class</CommandLine>
        <CommandLine condition="contains">Agent-Class</CommandLine>
        
        <!-- Redis进程 -->
        <Image condition="contains">redis-server</Image>
        <Image condition="contains">redis-cli</Image>
        
        <!-- MongoDB进程 -->
        <Image condition="contains">mongod.exe</Image>
        <Image condition="contains">mongo.exe</Image>
        
        <!-- Elasticsearch进程 -->
        <Image condition="contains">elasticsearch</Image>
        
        <!-- Nginx进程 -->
        <Image condition="contains">nginx</Image>
        
        <!-- 可疑子进程（从中间件启动） -->
        <ParentCommandLine condition="contains">java.exe</ParentCommandLine>
        <ParentCommandLine condition="contains">tomcat</ParentCommandLine>
        <ParentCommandLine condition="contains">weblogic</ParentCommandLine>
        
        <!-- 可疑命令执行 -->
        <CommandLine condition="contains">cmd.exe</CommandLine>
        <CommandLine condition="contains">powershell.exe</CommandLine>
        <CommandLine condition="contains">wscript.exe</CommandLine>
        <CommandLine condition="contains">cscript.exe</CommandLine>
        <CommandLine condition="contains">mshta.exe</CommandLine>
        <CommandLine condition="contains">certutil.exe</CommandLine>
        <CommandLine condition="contains">bitsadmin.exe</CommandLine>
        <CommandLine condition="contains">regsvr32.exe</CommandLine>
        <CommandLine condition="contains">rundll32.exe</CommandLine>
      </ProcessCreate>
    </RuleGroup>
    
    <!-- ============================================
         2. 文件创建监控 (Event ID 11)
         ============================================ -->
    <RuleGroup name="File Creation" groupRelation="or">
      <FileCreate onmatch="include">
        <!-- Tomcat webapps目录 -->
        <TargetFilename condition="contains">tomcat\webapps</TargetFilename>
        <TargetFilename condition="contains">tomcat/webapps</TargetFilename>
        
        <!-- WAR文件部署 -->
        <TargetFilename condition="end with">.war</TargetFilename>
        
        <!-- JSP文件创建 -->
        <TargetFilename condition="end with">.jsp</TargetFilename>
        <TargetFilename condition="end with">.jspx</TargetFilename>
        <TargetFilename condition="end with">.jsw</TargetFilename>
        <TargetFilename condition="end with">.jsv</TargetFilename>
        
        <!-- WebLogic部署目录 -->
        <TargetFilename condition="contains">weblogic</TargetFilename>
        <TargetFilename condition="contains">wlserver</TargetFilename>
        <TargetFilename condition="contains">user_projects\domains</TargetFilename>
        <TargetFilename condition="contains">autodeploy</TargetFilename>
        
        <!-- 配置文件修改 -->
        <TargetFilename condition="end with">web.xml</TargetFilename>
        <TargetFilename condition="end with">server.xml</TargetFilename>
        <TargetFilename condition="end with">context.xml</TargetFilename>
        <TargetFilename condition="end with">config.xml</TargetFilename>
        
        <!-- 可疑webshell文件名 -->
        <TargetFilename condition="contains">shell</TargetFilename>
        <TargetFilename condition="contains">cmd</TargetFilename>
        <TargetFilename condition="contains">exec</TargetFilename>
        <TargetFilename condition="contains">backdoor</TargetFilename>
        <TargetFilename condition="contains">hack</TargetFilename>
        
        <!-- JAR文件创建 -->
        <TargetFilename condition="end with">.jar</TargetFilename>
        
        <!-- Class文件创建（可能表明动态编译） -->
        <TargetFilename condition="end with">.class</TargetFilename>
      </FileCreate>
    </RuleGroup>
    
    <!-- ============================================
         3. 网络连接监控 (Event ID 3)
         ============================================ -->
    <RuleGroup name="Network Connection" groupRelation="or">
      <NetworkConnect onmatch="include">
        <!-- Java进程的网络连接 -->
        <Image condition="end with">java.exe</Image>
        <Image condition="end with">javaw.exe</Image>
        
        <!-- Tomcat网络连接 -->
        <Image condition="contains">tomcat</Image>
        
        <!-- WebLogic网络连接 -->
        <Image condition="contains">weblogic</Image>
        
        <!-- Redis网络连接 -->
        <Image condition="contains">redis</Image>
        
        <!-- MongoDB网络连接 -->
        <Image condition="contains">mongo</Image>
        
        <!-- Elasticsearch网络连接 -->
        <Image condition="contains">elasticsearch</Image>
        
        <!-- 可疑端口连接 -->
        <DestinationPort condition="is">4444</DestinationPort>
        <DestinationPort condition="is">5555</DestinationPort>
        <DestinationPort condition="is">6666</DestinationPort>
        <DestinationPort condition="is">7777</DestinationPort>
        <DestinationPort condition="is">8888</DestinationPort>
        <DestinationPort condition="is">9999</DestinationPort>
        <DestinationPort condition="is">12345</DestinationPort>
        <DestinationPort condition="is">31337</DestinationPort>
      </NetworkConnect>
    </RuleGroup>
    
    <!-- ============================================
         4. 注册表修改监控 (Event ID 12, 13, 14)
         ============================================ -->
    <RuleGroup name="Registry Events" groupRelation="or">
      <RegistryEvent onmatch="include">
        <!-- Java注册表项 -->
        <TargetObject condition="contains">JavaSoft\Java</TargetObject>
        
        <!-- Tomcat服务注册表 -->
        <TargetObject condition="contains">Tomcat</TargetObject>
        
        <!-- WebLogic服务注册表 -->
        <TargetObject condition="contains">WebLogic</TargetObject>
        
        <!-- 启动项监控 -->
        <TargetObject condition="contains">\Software\Microsoft\Windows\CurrentVersion\Run</TargetObject>
        <TargetObject condition="contains">\Software\Microsoft\Windows\CurrentVersion\RunOnce</TargetObject>
        <TargetObject condition="contains">\Software\Microsoft\Windows\CurrentVersion\RunOnceEx</TargetObject>
        
        <!-- 服务注册表 -->
        <TargetObject condition="contains">\System\CurrentControlSet\Services</TargetObject>
        
        <!-- Winlogon监控 -->
        <TargetObject condition="contains">\Software\Microsoft\Windows NT\CurrentVersion\Winlogon</TargetObject>
      </RegistryEvent>
    </RuleGroup>
    
    <!-- ============================================
         5. 驱动/模块加载监控 (Event ID 6, 7)
         ============================================ -->
    <RuleGroup name="Image Loading" groupRelation="or">
      <ImageLoad onmatch="include">
        <!-- Java相关DLL -->
        <ImageLoaded condition="contains">jvm.dll</ImageLoaded>
        <ImageLoaded condition="contains">java.dll</ImageLoaded>
        <ImageLoaded condition="contains">awt.dll</ImageLoaded>
        
        <!-- 可疑DLL加载 -->
        <ImageLoaded condition="contains">ws2_32.dll</ImageLoaded>
        <ImageLoaded condition="contains">wininet.dll</ImageLoaded>
        
        <!-- 反射DLL注入特征 -->
        <ImageLoaded condition="contains">ReflectiveDLLInjection</ImageLoaded>
      </ImageLoad>
    </RuleGroup>
    
    <!-- ============================================
         6. 管道创建监控 (Event ID 17, 18)
         ============================================ -->
    <RuleGroup name="Pipe Events" groupRelation="or">
      <PipeEvent onmatch="include">
        <!-- 命名管道监控 -->
        <PipeName condition="contains">tomcat</PipeName>
        <PipeName condition="contains">weblogic</PipeName>
        <PipeName condition="contains">java</PipeName>
        
        <!-- 可疑管道名 -->
        <PipeName condition="contains">msagent</PipeName>
        <PipeName condition="contains">win_svc</PipeName>
      </PipeEvent>
    </RuleGroup>
    
    <!-- ============================================
         7. WMI事件监控 (Event ID 19, 20, 21)
         ============================================ -->
    <RuleGroup name="WMI Events" groupRelation="or">
      <WmiEvent onmatch="include">
        <!-- 所有WMI事件订阅 -->
        <Operation condition="is">Created</Operation>
      </WmiEvent>
    </RuleGroup>
    
    <!-- ============================================
         8. DNS查询监控 (Event ID 22)
         ============================================ -->
    <RuleGroup name="DNS Query" groupRelation="or">
      <DnsQuery onmatch="include">
        <!-- Java进程DNS查询 -->
        <Image condition="end with">java.exe</Image>
        <Image condition="end with">javaw.exe</Image>
        
        <!-- 可疑域名 -->
        <QueryName condition="contains">.onion</QueryName>
        <QueryName condition="contains">.top</QueryName>
        <QueryName condition="contains">.xyz</QueryName>
        <QueryName condition="contains">.tk</QueryName>
        <QueryName condition="contains">.ml</QueryName>
      </DnsQuery>
    </RuleGroup>
    
    <!-- ============================================
         9. 剪贴板访问监控 (Event ID 24)
         ============================================ -->
    <RuleGroup name="Clipboard Events" groupRelation="or">
      <ClipboardChange onmatch="include">
        <!-- Java进程剪贴板访问 -->
        <Image condition="end with">java.exe</Image>
        <Image condition="end with">javaw.exe</Image>
      </ClipboardChange>
    </RuleGroup>
    
    <!-- ============================================
         10. 进程篡改监控 (Event ID 25)
         ============================================ -->
    <RuleGroup name="Process Tampering" groupRelation="or">
      <ProcessTampering onmatch="include">
        <!-- 所有进程篡改事件 -->
        <Type condition="is">Image is replaced by a different image (hollowing)</Type>
        <Type condition="is">Image is replaced by a different image (herpaderping)</Type>
      </ProcessTampering>
    </RuleGroup>
    
    <!-- ============================================
         排除规则（减少误报）
         ============================================ -->
    
    <!-- 排除常见良性进程 -->
    <ProcessCreate onmatch="exclude">
      <Image condition="end with">svchost.exe</Image>
      <Image condition="end with">lsass.exe</Image>
      <Image condition="end with">services.exe</Image>
      <Image condition="end with">smss.exe</Image>
      <Image condition="end with">csrss.exe</Image>
      <Image condition="end with">wininit.exe</Image>
      <Image condition="end with">winlogon.exe</Image>
      <Image condition="end with">explorer.exe</Image>
    </ProcessCreate>
    
    <!-- 排除常见良性网络连接 -->
    <NetworkConnect onmatch="exclude">
      <DestinationPort condition="is">80</DestinationPort>
      <DestinationPort condition="is">443</DestinationPort>
      <DestinationPort condition="is">53</DestinationPort>
      <DestinationPort condition="is">123</DestinationPort>
    </NetworkConnect>
    
  </EventFiltering>
  
</Sysmon>
```

---

#### 模板C: Sysmon部署脚本

```powershell
# ============================================
# Windows Sysmon 部署脚本
# ============================================

# 1. 下载Sysmon
$SysmonUrl = "https://download.sysinternals.com/files/Sysmon.zip"
$DownloadPath = "$env:TEMP\Sysmon.zip"
$ExtractPath = "$env:TEMP\Sysmon"

Invoke-WebRequest -Uri $SysmonUrl -OutFile $DownloadPath
Expand-Archive -Path $DownloadPath -DestinationPath $ExtractPath -Force

# 2. 下载配置（使用SwiftOnSecurity配置或自定义配置）
$ConfigUrl = "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml"
$ConfigPath = "$env:TEMP\sysmon-config.xml"

Invoke-WebRequest -Uri $ConfigUrl -OutFile $ConfigPath

# 3. 安装Sysmon
& "$ExtractPath\Sysmon64.exe" -accepteula -i $ConfigPath

# 4. 验证安装
Get-Service Sysmon64
Get-WinEvent -ListLog Microsoft-Windows-Sysmon/Operational

# 5. 更新配置（如果需要）
# & "$ExtractPath\Sysmon64.exe" -c $ConfigPath

# 6. 卸载Sysmon（如需要）
# & "$ExtractPath\Sysmon64.exe" -u

Write-Host "Sysmon installation completed!"
```

---

#### 模板D: Auditd部署脚本

```bash
#!/bin/bash
# ============================================
# Linux Auditd 部署脚本
# ============================================

# 1. 安装auditd
if command -v apt-get &> /dev/null; then
    apt-get update && apt-get install -y auditd audispd-plugins
elif command -v yum &> /dev/null; then
    yum install -y audit audit-libs
elif command -v dnf &> /dev/null; then
    dnf install -y audit audit-libs
fi

# 2. 启用并启动服务
systemctl enable auditd
systemctl start auditd

# 3. 创建自定义规则目录
mkdir -p /etc/audit/rules.d/

# 4. 部署规则文件（将上面的规则保存到此文件）
cat > /etc/audit/rules.d/middleware-security.rules << 'EOF'
# 将上面的auditd规则粘贴到这里
EOF

# 5. 加载规则
auditctl -R /etc/audit/rules.d/middleware-security.rules

# 6. 重启auditd以应用规则
service auditd restart

# 7. 验证规则加载
auditctl -l | head -20

# 8. 检查日志
ausearch -ts recent -k tomcat_webapp_deploy

# 9. 配置日志轮转
cat > /etc/logrotate.d/audit << 'EOF'
/var/log/audit/audit.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0600 root root
    sharedscripts
    postrotate
        /sbin/service auditd restart > /dev/null 2>&1 || true
    endscript
}
EOF

echo "Auditd installation and configuration completed!"
```

---

## 4. 使用说明

### 4.1 三维检测方案部署流程

```
┌─────────────────────────────────────────────────────────────────┐
│                    中间件漏洞三维检测方案                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. 网络层资产发现                                               │
│     ├── 端口扫描 (Nmap/Masscan)                                 │
│     ├── Banner指纹识别                                           │
│     └── 服务版本识别                                             │
│                                                                  │
│  2. 应用层POC验证                                                │
│     ├── Python POC脚本                                          │
│     ├── Nuclei YAML模板                                         │
│     └── 漏洞验证与利用                                           │
│                                                                  │
│  3. 主机层HIDS/EDR监控                                           │
│     ├── Sigma规则 (SIEM集成)                                    │
│     ├── Yara规则 (恶意代码检测)                                  │
│     └── Auditd/Sysmon (系统监控)                                │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 4.2 快速部署命令

```bash
# 1. 网络层扫描
nmap -sV -p 80,443,8080,7001,6379,9200,27017,3306,2375,2181 192.168.1.0/24

# 2. 应用层POC扫描
nuclei -t middleware-vulnerabilities/ -l targets.txt

# 3. 主机层监控
# Linux: 部署auditd规则
auditctl -R /etc/audit/rules.d/middleware-security.rules

# Windows: 部署Sysmon
Sysmon64.exe -accepteula -i sysmon-middleware-config.xml
```

### 4.3 日志分析查询

```bash
# Auditd日志分析
# 查看Tomcat WAR部署事件
ausearch -ts today -k tomcat_webapp_deploy

# 查看Java进程执行
ausearch -ts today -k java_execution

# 查看配置文件修改
ausearch -ts today -k tomcat_config_change

# 生成审计报告
aureport --login --summary -i
aureport --user -i --summary
aureport --executable -i --summary
```

---

*文档生成时间: 2024年*  
*版本: 1.0*  
*维护团队: 企业安全团队*
