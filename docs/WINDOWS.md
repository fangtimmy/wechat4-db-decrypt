# Windows 说明

本文档描述 Windows 端微信 4.x 的数据发现、密钥抓取、快照、解密与导出流程。
macOS 的 SIP/Gadget 链路见项目主 [README](../README.md)。

## 已验证环境

- Windows 10/11 x64
- 微信 `4.1.15.13`（`C:\Program Files\Tencent\Weixin\Weixin.exe`）
- Python 3.14 + pycryptodome/zstandard（`uv sync --frozen` 或 pip）
- 普通用户完整性即可读取进程内存；部分环境可能需要管理员
- 本机验证：`Config.Cipher` 扫描 20/20 个数据库通过 HMAC，解密 20/20 成功；
  合成 SQLCipher 测试 42 项通过

## 数据目录

微信 4.x 的真实数据根目录记录在：

```text
%APPDATA%\Tencent\xwechat\config\<hash>.ini
```

文件内容是一行路径，例如 `D:\微信`。实际数据库位于：

```text
<数据根目录>\xwechat_files\<wxid>_<后缀>\db_storage\
```

`%USERPROFILE%\Documents\xwechat_files` 只作为回退。用户迁移过数据后，旧账号
目录可能仍留在 `Documents`，所以不能只认默认路径。工具会：

1. 读取所有 `*.ini`（UTF-8/GBK），并加入 `Documents` 回退；
2. 枚举每个根目录下的 `xwechat_files\*\db_storage`；
3. 用 `db_storage` 最近文件时间排序；
4. 终端交互时列出候选让用户选择；`-Yes` 或非交互模式选择最近使用的目录；
5. 也可用 `-DbDir` / `--db-dir` 直接指定。

## 密钥抓取

微信 4.1.10+ 不再把 `x'<64hex key><32hex salt>'` 明文缓存在进程内存。Windows
端按以下顺序尝试：

| 策略 | 适用版本 | 说明 |
|---|---|---|
| `Config.Cipher` 运行时只读扫描 | 4.1.11–4.1.15（已验证） | 默认主路径 |
| 旧式 `x'...'` 内存扫描 | 4.0.x–4.1.9 | 自动回退 |
| passphrase → PBKDF2-HMAC-SHA512（256,000 轮） | 某些 4.1.x | `--deep` / `--passphrase` |
| 手动 key / key 文件 | 所有版本 | 保底；仍必须 HMAC 验证 |
| Frida spawn hook | 未来版本 | `--inject`，实验性，需先退出微信 |

所有策略只接受通过数据库第 1 页 HMAC-SHA512 校验的候选。扫描器不修改微信
进程，不注入代码，不写微信文件。

### Config.Cipher 扫描

当前版本的对象布局（集中在 `src/wxexport/win/profiles.py`）：

```text
锚点字符串: com.Tencent.WCDB.Config.Cipher
字符串引用节点 = 引用地址 - 0x10
node+0x10 = 字符串指针
node+0x18 = 字符串长度
node+0x28 = 配置对象指针
config+0x88 = blob 描述对象
blob_obj+0x08 = blob 数据指针
blob_obj+0x10 = blob 长度（<= 1024）
XOR mask = d2c7442458020000004889442450488b450048844c2448488944254048584c24
```

对 blob 做 32 字节循环 XOR 后匹配 `x'<64-192 hex>'`，提取 key/salt，再用每个
数据库自己的 salt 验证首页 HMAC。不同版本的偏移或 mask 可能变化，届时更新
profile；未知版本会尝试全部 profile，并保留手动导入路径。

## 数据快照

Windows 没有 APFS 写时复制，工具用普通复制：

```text
<项目>\.runtime\win-snapshot\
├── .snapshot.json
├── contact\contact.db
├── message\message_0.db
└── ...（含 -wal / -shm）
```

- 优先 `robocopy /E /COPY:DAT /R:2 /W:1`，失败回退逐文件 `copy2`
- 标记记录源路径、版本、时间、文件数
- 默认复用匹配的旧快照；`--refresh-snapshot` 原子替换
- 解密默认读取快照；如快照缺失/不匹配则回退实时目录
- 微信升级、账号切换、迁移后请刷新快照

## 使用

```powershell
# 一键
.\run.bat
.\run.ps1 -Output D:\WeChat-Export

# 跳过抓取，复用密钥
.\run.ps1 -NoHunt

# 刷新快照并重新抓取
.\run.ps1 -RefreshSnapshot

# 多个账号
.\run.ps1 -DbDir "D:\微信\xwechat_files\<wxid>_xxxx\db_storage"

# 手动 key/passphrase
.\run.ps1 -Passphrase <64位hex>
.\run.ps1 -KeyFile .\keys.json
```

分步：

```powershell
python -m wxexport.keys.hunt
python -m wxexport.keys.map
python -m wxexport.decrypt
python -m wxexport.export.all --output .\exported_all
```

### 参数

| 参数 | 说明 |
|---|---|
| `-NoHunt` | 跳过抓取，复用 `hunted_keys.txt`/`all_keys.json` |
| `-NoRestart` | 兼容参数；Windows 默认读取运行中的微信 |
| `-RefreshSnapshot` | 重建数据快照，不可与 `-NoHunt` 同用 |
| `-Output` | 导出目录 |
| `-DbDir` | 指定 `db_storage` |
| `-Passphrase` | 手动 32 字节 passphrase（64 hex） |
| `-KeyFile` | 手动 key 文件（JSON 或每行 hex） |
| `-DbKey` | 手动 key，可重复；`相对路径=64hex` 或 `64hex` |
| `-Deep` | 额外尝试 passphrase/PBKDF2 扫描（较慢） |
| `-Inject` | 实验性 Frida spawn hook；需先退出微信 |
| `-NoSnapshot` | 抓取后不建立快照 |
| `-Yes` | 非交互，自动选择最近使用的账号目录 |

## 手动密钥

`keys.json` 支持：

```json
{
  "message/message_0.db": {"enc_key": "<64hex>"},
  "contact/contact.db": "<64hex>"
}
```

也支持 `hunted_keys.txt` 形式的每行 64/96 hex。`passphrase` 是账号级 32 字节
原料，工具会用每个库自己的 salt 做 PBKDF2-HMAC-SHA512（256,000 轮）派生
enc_key，再验证 HMAC。

`all_keys.json` 中下划线开头的 `_meta` 字段不参与解密。密钥文件权限会被限制
为当前用户（`icacls`），但请仍然妥善保管。

## 故障排查

**自动检测到多个目录 / 选错账号**
用 `-DbDir` 指定当前登录账号的 `db_storage`，或删除 `config.json` 重新检测。
`Documents` 下的旧副本通常不是当前账号。

**`Config.Cipher` 扫描 0 个，或只有部分库**
1. 确认微信已登录且数据目录正确；
2. `--refresh-snapshot` 后重试；
3. 在微信中打开对应功能（通讯录、收藏、朋友圈）后重试；
4. 版本升级可能改变对象布局，使用 `-Passphrase`/`-KeyFile` 手动兜底；
5. 仍失败时不要使用未验证的 key，工具会拒绝写入。

**无法读取进程内存（Win32 错误 5）**
以管理员身份运行 PowerShell 后重试；或使用手动 key。

**快照/解密文件被占用**
先退出微信再 `-RefreshSnapshot`；解密默认读快照，不应与微信直接争用文件。
如仍失败，关闭杀毒软件对项目 `.runtime`/`decrypted` 的实时扫描后重试。

**导出目录重名/被占用**
工具会在同目录创建 staging 后原子替换；Windows 下若目标被占用会重试，最终
失败时保留已有目录并报错，不会删除原数据。

**路径过长/中文路径**
Python 3.6+ 在启用长路径的系统上可处理长路径；仍建议把导出目录放在较短的
英文路径下。

## 安全与限制

- 仅用于导出本人账号的本地数据；不要用于他人设备或未经授权的数据
- 默认不注入、不 Hook、不联网；`--inject` 是显式实验路径，存在被检测/封号
  风险，且当前 4.1.15 的已验证路径不需要它
- 密钥、解密库、导出结果都是敏感数据。`all_keys.json` 等同于全部聊天解密
  能力，不要提交到 git 或分享
- 媒体文件本体不导出；只输出占位符和元数据
- `migrate/unspportmsg.db`、`biz_message_0.db` 等可能缺少密钥；不影响已覆盖
  的会话
- 微信升级、账号切换、迁移后密钥/快照可能失效，需要重新抓取

## 测试

```powershell
$env:PYTHONPATH = "src"
python -m unittest discover -s tests -v
```

测试使用合成 SQLCipher 4 数据库（含 `reserve=80`、HMAC、zstd、群聊/自身
识别），不读取真实聊天数据。

## 归属

Windows `Config.Cipher` 扫描算法来自
[TANGandXUE/wcdb-key-tool](https://github.com/TANGandXUE/wcdb-key-tool)
（MIT）。本项目将其整理进 `win/keyscan.py`，并增加多进程、legacy、passphrase、
手动 key 和快照流程。版本演进参考
[NinjaSln-labs/wxlocal](https://github.com/NinjaSln-labs/wxlocal) 的 4.1.x 研究
记录。本项目整体仍按 WTFPL 发布。
