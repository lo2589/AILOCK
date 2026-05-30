# AiLock

**加密你的代码，AI 看不到，但你照常用。**

AiLock 将文件原地加密为二进制乱码。AI 的 `read_file`、`grep`、`cat` 全部失效。但你可以直接执行加密代码、编辑加密文件——一切透明，零侵入。

## 核心理念

```
磁盘：乱码（AI 看到的）
内存：明文（你的代码在跑）
```

## 安装

```bash
pip install .
```

或开发模式：

```bash
pip install argon2-cffi cryptography pyzipper
python -m aloc --help
```

## 快速开始

```bash
# 加密文件（原地变乱码）
ailock lock secret.py

# AI 看到什么？
cat secret.py        # → 二进制乱码
grep "password" .    # → 什么都找不到

# 你看到什么？
ailock show secret.py       # → 明文内容
ailock run main.py          # → 直接执行（加密文件透明解密）
ailock open src/            # → GUI 编辑器

# 解密还原
ailock unlock secret.py
```

## 核心命令

### `ailock lock <path>`

原地加密文件或目录。加密后 AI 无法读取。

- 支持单文件和目录递归加密
- 自动创建加密备份到 `.ailock/backups/`
- 支持 `--recovery` 生成恢复密钥

```bash
ailock lock config.py
ailock lock src/              # 递归加密整个目录
ailock lock secret.env --recovery
```

### `ailock run <target>`

**在内存中执行加密代码，磁盘永远是密文。**

支持所有 Python 启动方式：

```bash
ailock run main.py                 # 直接文件
ailock run -m mypackage            # 模块模式（等价 python -m）
ailock run mypackage/              # 目录模式（找 __main__.py）
ailock run app.py -- --port 8080   # 带参数
```

透明拦截层：
- 自定义 import hook：加密模块间互相导入正常工作
- 透明文件 I/O：`open("config.json")` 自动解密返回明文
- `Path.read_text()` / `json.load()` 全部无感工作
- AI 的 `grep`/`cat`/`read_file` 只能看到乱码

```python
# main.py 里正常写代码，完全不需要知道 ailock 的存在：
import json
from secret_module import algo    # 加密的模块，自动解密导入

with open("config.json") as f:    # 加密的 JSON，透明解密
    config = json.load(f)
```

### `ailock open [path]`

弹出 GUI 编辑器，左栏文件树 + 右栏解密编辑。

- 后台线程解密，UI 不卡
- Ctrl+S 保存时自动重新加密
- 密码只输一次

```bash
ailock open src/
ailock open           # 当前目录
```

### `ailock freelock [path]`

启动 JSON-RPC 解密工作区（给外部框架/本地 LLM 对接用）。

```bash
ailock freelock src/
```

通过 stdin/stdout 交互：
```json
{"method": "read_file", "params": {"path": "main.py"}, "id": 1}
{"method": "write_file", "params": {"path": "main.py", "content": "..."}, "id": 2}
{"method": "grep", "params": {"pattern": "TODO"}, "id": 3}
{"method": "flush", "params": {}, "id": 4}
```

或 Python 直接调用：
```python
from aloc.workspace import DecryptedWorkspace

ws = DecryptedWorkspace("/project", password="xxx")
ws.load()
content = ws.read_file("secret.py")
ws.write_file("secret.py", modified)
ws.flush()  # 加密写回磁盘
```

### `ailock unlock <path>`

解密还原文件或目录。

- 文件被 AI 篡改导致损坏时，自动从备份恢复
- 支持 `--backup` 在解密前额外创建 .bak

```bash
ailock unlock config.py
ailock unlock src/           # 递归解密整个目录
```

### `ailock show <file>`

解密并输出内容到终端（不修改文件）。

```bash
ailock show secret.py | head -20
```

### 其他命令

```bash
ailock status file.py        # 检查是否加密（输出 locked/plain）
ailock config backup-dir ~/x # 设置备份目录
ailock recover file.py       # 用恢复密钥解密（忘记密码时）
ailock forget                # 清除缓存密钥
ailock init --as al          # 安装为短命令
```

## 工作原理

### 为什么 AI 看不到？

AI coding assistant（Cursor、Copilot、Claude Code 等）通过 `read_file`、`grep`、`cat` 等工具访问文件。加密后这些工具只能看到二进制乱码。

### 为什么你能用？

`ailock run` 在启动时注册三层透明拦截：

1. **Import Hook** (`sys.meta_path`) — `import secret_module` 自动解密
2. **IO Patch** (`builtins.open`) — `open("config.json")` 自动解密
3. **Pathlib Patch** — `Path("f").read_text()` 自动解密

代码不需要任何修改，像文件就在那里一样。

### 加密架构

```
密码 → Argon2id → 密码密钥 ─┐
                              ├→ 包装 → 文件密钥 → ChaCha20-Poly1305 → 密文
恢复密钥 → Argon2id → 恢复密钥 ┘
```

### 备份恢复策略

当文件被 AI 损坏导致 unlock 失败时，三级回退：

1. **精确路径匹配** — 文件没动过
2. **Hash 匹配** — 文件被移走，内容没变
3. **文件名匹配** — 最坏情况（移走且内容被改）

### 密码缓存

类似 `sudo`：输入一次密码后缓存 5 分钟，期间操作同项目文件无需重复输入。

## 项目结构

```
aloc/
├── cli.py           # 命令行接口
├── runner.py        # 内存执行引擎 (import hook + IO patch)
├── workspace.py     # 解密工作区 API (JSON-RPC)
├── gui.py           # tkinter GUI 编辑器
├── crypto.py        # 加密原语 (Argon2id, ChaCha20-Poly1305)
├── format.py        # 文件格式编解码
├── fileops.py       # 原子写入、安全备份
├── cache.py         # sudo 风格密码缓存
├── manifest.py      # 备份清单管理
├── recovery.py      # 恢复密钥系统
└── install.py       # 自定义命令安装
```

## 安全特性

- **Argon2id** 密钥派生（抗 GPU/ASIC 暴力破解）
- **ChaCha20-Poly1305** 认证加密（防篡改检测）
- **独立文件密钥** 每个文件使用随机密钥
- **内存隔离** 明文只存在于进程内存，从不落盘
- **AES-256 ZIP 备份** 备份同样加密保护
- **原子写入** 防止加密过程中断导致数据丢失

## 依赖

- `argon2-cffi` — Argon2id 密钥派生
- `cryptography` — ChaCha20-Poly1305 AEAD
- `pyzipper` — AES-256 加密 ZIP
- `tkinter` — GUI（Python 自带）

## License

MIT
