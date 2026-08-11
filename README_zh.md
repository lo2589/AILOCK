# AILatch

**AILatch 给源代码加密，加密后的代码借助 AILatch 依然能正常运行。**

常见的 AI 代码助手 Cursor、Claude Code 等等，往往会把整个项目读一遍。AILatch 让你把不想给它们看的文件锁起来：

- **AI 只能看到乱码**：`cat`、`grep`、代码索引器打开加密文件，读到的是二进制乱码文件。
- **不解密就能运行代码**：`ailatch run main.py` 直接运行，加密的模块正常 `import`，加密的 JSON 和配置正常 `open()` 读。
- **明文只在内存里**：磁盘上一直是密文，不会在旁边多出一份明文副本。
- **随时能看能改**：`ailatch show` 看内容，`ailatch open` 在图形界面里改，存盘自动加密回去。

```bash
ailatch lock main.py      # 加密
cat main.py              # 乱码
grep -r "API_KEY" .      # 搜不到
ailatch run main.py       # 照常运行
```

English README: [README.md](README.md)

已在 Windows 和 macOS 开发场景下测试。

## 环境要求

- Python 3.11 或更高版本
- `pip`
- 运行依赖会从 `pyproject.toml` 自动安装：`argon2-cffi`、`cryptography`、`pyzipper`
- `ailatch open` 需要 `tkinter`；很多 Python 发行版自带，部分 Linux 发行版需要单独安装 `python3-tk`
- 主要测试桌面开发环境为 Windows 和 macOS。

## 安装指南

从 GitHub 安装：

```bash
git clone https://github.com/lo2589/AILATCH.git
cd AILATCH
pip install .
```

开发模式安装：

```bash
git clone https://github.com/lo2589/AILATCH.git
cd AILATCH
pip install -e .
```

检查命令：

```bash
ailatch --help
```

如果 `ailatch` 不在 `PATH` 中，也可以用模块入口：

```bash
python -m ailatch --help
```

## 快速开始

```bash
# 原地加密文件
ailatch lock secret.py

# AI 和普通文件工具只能看到密文
cat secret.py
grep "password" .

# 开发者仍然可以使用
ailatch show secret.py
ailatch run secret.py
ailatch open .

# 需要时恢复为磁盘明文
ailatch unlock secret.py
```

## 内存解密执行

`ailatch run` 是 AILatch 的核心能力。它会在内存中解密入口文件，在 Python 进程内执行明文代码，并让工作区文件继续保持密文。不会在加密文件旁边生成明文副本。

```bash
ailatch run main.py
ailatch run -m mypackage
ailatch run app.py -- --port 8080
```

运行时数据流：

```text
磁盘加密 .py 文件 -> 内存解密 -> Python exec/import
磁盘加密数据文件  -> 内存解密 -> open()/Path.read_text()
```

你的业务代码不需要知道 AILatch 的存在：

```python
import json
from secret_module import algorithm

with open("config.json") as f:
    config = json.load(f)

print(algorithm(config))
```

如果 `secret_module.py` 或 `config.json` 是加密文件，AILatch 会在运行时透明解密；但磁盘上仍然是密文。

## 主要命令

### `ailatch lock <path>`

原地加密文件或目录。

```bash
ailatch lock secret.py
ailatch lock src/
ailatch lock secret.py --recovery
```

说明：

- 目录会递归处理。
- 已加密文件会跳过。
- 默认会把明文备份加密保存到 `.ailatch/backups/`。
- `--recovery` 会生成恢复密钥，请单独保存；之后不会再次显示。

### `ailatch run <path>`

在不把明文写回磁盘的情况下运行加密 Python 代码。

```bash
ailatch run main.py
ailatch run -m mypackage
ailatch run app.py -- --port 8080
```

运行时拦截层：

- import hook：加密模块可正常导入
- `builtins.open` patch：运行时透明读取加密文件
- `pathlib.Path.read_text/read_bytes` patch：常见文件读取方式可用

### `ailatch open [path]`

打开 GUI 明文视图/编辑器。

```bash
ailatch open .
ailatch open src/
```

加密文件会被解密显示。保存时重新加密写回磁盘。

### `ailatch show <file>`

把解密内容输出到终端，不修改原文件。

```bash
ailatch show secret.py
ailatch show secret.py | head
```

### `ailatch unlock <path>`

把文件或目录恢复为磁盘明文。

```bash
ailatch unlock secret.py
ailatch unlock src/ --backup
```

### `ailatch recover <file>`

使用恢复密钥恢复文件。

```bash
ailatch recover secret.py
```

### `ailatch restore <file>`

从 manifest 记录的加密备份恢复原始明文。工作文件损坏或丢失时也可以恢复。

```bash
ailatch restore secret.py
ailatch restore secret.py --backup
```

### `ailatch freelock [path]`

启动 stdin/stdout JSON-RPC 工作区，用于受控地向外部工具提供明文访问。

```bash
ailatch freelock .
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
ailatch status file.py
ailatch forget
ailatch forget --all
ailatch config
ailatch config backup-dir /path/to/backups
ailatch init --as aa
```

`ailatch init --as <name>` 可以安装自定义命令名。这样在本地部署中，解锁入口名称不必固定为 `ailatch`。

## 安全边界

AILatch 主要防的是**文件系统级 AI 读取**：AI 助手通过 `read_file`、`grep`、`cat`、索引器读取项目文件时，只能拿到密文。

AILatch 不声称能阻止完全知情、可任意执行命令、可读进程内存的本地攻击者。需要更强隔离时，应结合操作系统执行策略、进程隔离和更严格的密钥管理。

## 加密设计

- Argon2id 派生密码密钥
- ChaCha20-Poly1305 认证加密
- 每个文件独立随机 file key
- password wrapping 保护 file key
- 可选 recovery key wrapping
- AES-256 ZIP 加密备份用于应急恢复

## 项目结构

```text
ailatch/
  cli.py        命令行入口
  runner.py     内存执行引擎
  workspace.py  解密工作区 API 和 JSON-RPC handler
  gui.py        tkinter GUI 编辑器
  crypto.py     Argon2id / ChaCha20-Poly1305
  format.py     加密文件格式
  fileops.py    原子写入和备份
  cache.py      类 sudo 的密码缓存
  manifest.py   .ailatch 清单和备份管理
  recovery.py   恢复密钥
  install.py    自定义命令名安装
```

## 依赖摘要

- `argon2-cffi`
- `cryptography`
- `pyzipper`
- `tkinter`，多数 Python 安装自带，用于 GUI

## License

MIT
