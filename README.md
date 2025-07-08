# CollectProxySource

copy https://github.com/RenaLio/proxy-minging/

## 说明

Config.yaml	--- 爬取源

main.py --- 主程序

pre_check.py --- 运行前检查，主要检测输出的路径文件夹是否存在，(不存在->创建)

requirements.txt --- 依赖包

## 新增功能

### 节点过滤功能

本项目已集成智能节点过滤系统，自动过滤以下类型的节点：

#### 🔍 **过滤规则**

1. **纯IP节点过滤**
   - 自动过滤所有IPv4和IPv6地址的节点
   - 只保留域名节点，提高节点质量

2. **Cloudflare节点过滤**
   - 过滤所有Cloudflare域名的http/https端口节点
   - 包含 `cloudflare.com` 和 `.cloudflare-` 域名的节点
   - 过滤端口：80, 443

3. **指定端口过滤**
   - 过滤以下端口的节点：
     - 80, 8080, 8880
     - 2052, 2082, 2086, 2095
     - 443, 2053, 2083, 2087, 2096
     - 8443

#### 🚀 **功能特点**

- **实时过滤**：在订阅检测和节点处理过程中实时应用过滤规则
- **智能识别**：自动识别各种节点协议（ss://, ssr://, vmess://, vless://, trojan://, hysteria://等）
- **日志记录**：详细记录过滤过程，便于调试和监控
- **性能优化**：高效的过滤算法，不影响处理速度

#### 📁 **输出文件**

过滤后的节点将保存在以下文件中：
- `config_all_merged_nodes.txt` - 主要合并节点文件
- `config_clash.txt` - Clash格式配置
- `config_loon.txt` - Loon格式配置
- `config_sub_store.txt` - 订阅存储格式

#### 🔧 **使用方法**

1. 确保安装了所有依赖：
   ```bash
   pip install -r requirements.txt
   ```

2. 配置 `config.yaml` 文件，设置爬取源

3. 运行主程序：
   ```bash
   python main.py
   ```

4. 程序将自动应用过滤规则，输出高质量的节点文件

#### 📊 **过滤效果**

- 自动过滤低质量节点
- 保留高质量域名节点
- 提高节点可用性和稳定性
- 减少无效节点对性能的影响

## 文件结构

```
collectSub/
├── main.py              # 主程序（包含节点过滤功能）
├── generate_nodes.py    # 节点生成器
├── pre_check.py         # 运行前检查
├── config.yaml          # 配置文件
├── requirements.txt     # 依赖包
├── output/              # 输出目录
└── sub/                 # 订阅文件目录
```

## 更新日志

### 最新更新
- ✅ 添加智能节点过滤功能
- ✅ 过滤纯IP节点、Cloudflare节点和指定端口节点
- ✅ 优化节点质量，提高可用性
- ✅ 清理历史残留文件，优化项目结构

