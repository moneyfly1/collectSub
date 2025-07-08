import base64
import re
import os
import tempfile
import subprocess

ALL_TXT_PATH = 'output/all.txt'
XR_TXT_PATH = 'xr.txt'

# 读取并解码 all.txt
with open(ALL_TXT_PATH, 'r', encoding='utf-8') as f:
    b64_content = f.read()

try:
    decoded = base64.b64decode(b64_content).decode('utf-8')
except Exception as e:
    print('Base64 decode error:', e)
    exit(1)

# 分割节点（每行为一个节点）
lines = [line.strip() for line in decoded.splitlines() if line.strip()]

# 匹配节点类型
node_pattern = re.compile(r'^(ss|ssr|vmess|vless|trojan|hysteria|hy|hy2)://')

# 提取主机名（仅支持部分协议，复杂协议可扩展）
def extract_host(node):
    # 这里只做简单提取，复杂协议建议用专用库
    if node.startswith('ss://') or node.startswith('ssr://'):
        # ss/ssr: ss://base64@host:port
        m = re.search(r'@([\w\.-]+):\d+', node)
        if m:
            return m.group(1)
    elif node.startswith('vmess://'):
        try:
            import json
            vmess_json = base64.b64decode(node[8:] + '===').decode('utf-8')
            obj = json.loads(vmess_json)
            return obj.get('add')
        except Exception:
            return None
    elif node.startswith('vless://') or node.startswith('trojan://'):
        m = re.match(r'\w+://([^:@]+)', node)
        if m:
            return m.group(1)
    return None

# 测速函数（用 speedtest-cli 测速本地网络，节点测速需用代理工具或专用库）
def speedtest_node(host):
    # 这里只做 ping 检查，实际节点测速建议用 clash/sing-box 等代理工具
    try:
        result = subprocess.run(['ping', '-c', '1', '-W', '1', host], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return result.returncode == 0
    except Exception:
        return False

passed_nodes = []
for node in lines:
    if not node_pattern.match(node):
        continue
    host = extract_host(node)
    if not host:
        continue
    print(f'Testing {host} ...')
    if speedtest_node(host):
        passed_nodes.append(node)
        print(f'PASS: {host}')
    else:
        print(f'FAIL: {host}')

print(f'通过测速的节点数: {len(passed_nodes)}')

# 合并并 base64 编码
if passed_nodes:
    merged = '\n'.join(passed_nodes)
    with open(XR_TXT_PATH, 'wb') as f:
        f.write(base64.b64encode(merged.encode('utf-8')))
    print(f'已生成 {XR_TXT_PATH}')
else:
    print('没有节点通过测速') 