# AiLock

**代码在磁盘上是密文，只在内存中解密，但仍然可以直接运行。**

AiLock 的重点不是“把文件加密后就不能用了”，而是：

> **AI 读文件时只能看到密文；开发者运行代码时，明文只在受控进程内存中出现。**

也就是说：

```text
磁盘工作区: 密文, AI/read_file/grep/cat/code indexer 看到这里
运行时内存: 明文, 你的 Python 程序在这里正常 import/open/read
```

English README: [README.md](README.md)

## 核心卖点：可运行加密代码

普通加密工具通常会让代码在解密前不可运行。AiLock 的目标不同：

- `ailock lock app.py` 后，`app.py` 在磁盘上变成二进制密文。
- AI 助手、`cat`、`grep`、索引器读到的都是密文。
- 你仍然可以 `ailock run app.py`，代码只在内存中解密并执行。
- AiLock 不会为了运行代码而把明文文件恢复到工作区。
- 被加密的 Python 模块仍可正常 `import`。
- 被加密的 JSON/TXT/配置文件仍可通过 `open()` 或 `Path.read_text()` 在运行时透明读取。
- `ailock open` 提供 GUI 明文视图，保存时重新写回密文。

最小例子：

```bash
ailock lock main.py
cat main.py              # 看到密文
grep "password" .        # 搜不到明文
ailock run main.py       # 正常运行加密代码
```

## 安装

在仓库目录中：

```bash
pip install .
```

开发模式：

```bash
pip install -e .
python -m aloc --help
```

安装后命令为：

```bash
ailock --help
```

## 快速开始

```bash
# 原地加密文件
ailock lock secret.py

# AI 和普通文件工具只能看到密文
cat secret.py
grep "password" .

# 开发者仍然可以使用
ailock show secret.py
ailock run secret.py
ailock open .

# 需要时恢复为磁盘明文
ailock unlock secret.py
```

## 内存解密执行

`ailock run` 是 AiLock 的核心能力。它会在内存中解密入口文件，在 Python 进程内执行明文代码，并让工作区文件继续保持密文。不会在加密文件旁边生成明文副本。

```bash
ailock run main.py
ailock run -m mypackage
ailock run app.py -- --port 8080
```

运行时数据流：

```text
磁盘加密 .py 文件 -> 内存解密 -> Python exec/import
磁盘加密数据文件  -> 内存解密 -> open()/Path.read_text()
```

你的业务代码不需要知道 AiLock 的存在：

```python
import json
from secret_module import algorithm

with open("config.json") as f:
    config = json.load(f)

print(algorithm(config))
```

如果 `secret_module.py` 或 `config.json` 是加密文件，AiLock 会在运行时透明解密；但磁盘上仍然是密文。

## 主要命令

### `ailock lock <path>`

原地加密文件或目录。

```bash
ailock lock secret.py
ailock lock src/
ailock lock secret.py --recovery
```

说明：

- 目录会递归处理。
- 已加密文件会跳过。
- 默认会把明文备份加密保存到 `.ailock/backups/`。
- `--recovery` 会生成恢复密钥，请单独保存；之后不会再次显示。

### `ailock run <path>`

在不把明文写回磁盘的情况下运行加密 Python 代码。

```bash
ailock run main.py
ailock run -m mypackage
ailock run app.py -- --port 8080
```

运行时拦截层：

- import hook：加密模块可正常导入
- `builtins.open` patch：运行时透明读取加密文件
- `pathlib.Path.read_text/read_bytes` patch：常见文件读取方式可用

### `ailock open [path]`

打开 GUI 明文视图/编辑器。

```bash
ailock open .
ailock open src/
```

加密文件会被解密显示。保存时重新加密写回磁盘。

### `ailock show <file>`

把解密内容输出到终端，不修改原文件。

```bash
ailock show secret.py
ailock show secret.py | head
```

### `ailock unlock <path>`

把文件或目录恢复为磁盘明文。

```bash
ailock unlock secret.py
ailock unlock src/ --backup
```

### `ailock recover <file>`

使用恢复密钥恢复文件。

```bash
ailock recover secret.py
```

### `ailock freelock [path]`

启动 stdin/stdout JSON-RPC 工作区，用于受控地向外部工具提供明文访问。

```bash
ailock freelock .
```

示例请求：

```json
{"method": "list_files", "params": {}, "id": 1}
{"method": "read_file", "params": {"path": "main.py"}, "id": 2}
{"method": "grep", "params": {"pattern": "TODO"}, "id": 3}
{"method": "write_file", "params": {"path": "main.py", "content": "..."}, "id": 4}
{"method": "flush", "params": {}, "id": 5}
```

## 其他命令

```bash
ailock status file.py
ailock forget
ailock forget --all
ailock config
ailock config backup-dir /path/to/backups
ailock init --as aa
```

`ailock init --as <name>` 可以安装自定义命令名。这样在本地部署中，解锁入口名称不必固定为 `ailock`。

## 安全边界

AiLock 主要防的是**文件系统级 AI 读取**：AI 助手通过 `read_file`、`grep`、`cat`、索引器读取项目文件时，只能拿到密文。

AiLock 不声称能阻止完全知情、可任意执行命令、可读进程内存的本地攻击者。需要更强隔离时，应结合操作系统执行策略、进程隔离和更严格的密钥管理。

## 加密设计

- Argon2id 派生密码密钥
- ChaCha20-Poly1305 认证加密
- 每个文件独立随机 file key
- password wrapping 保护 file key
- 可选 recovery key wrapping
- AES-256 ZIP 加密备份用于应急恢复

## 项目结构

```text
aloc/
  cli.py        命令行入口
  runner.py     内存执行引擎
  workspace.py  解密工作区 API 和 JSON-RPC handler
  gui.py        tkinter GUI 编辑器
  crypto.py     Argon2id / ChaCha20-Poly1305
  format.py     加密文件格式
  fileops.py    原子写入和备份
  cache.py      类 sudo 的密码缓存
  manifest.py   .ailock 清单和备份管理
  recovery.py   恢复密钥
  install.py    自定义命令名安装
```

## 依赖

- `argon2-cffi`
- `cryptography`
- `pyzipper`
- `tkinter`，多数 Python 安装自带，用于 GUI

## License

MIT
