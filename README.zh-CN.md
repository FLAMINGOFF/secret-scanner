# 密钥泄露扫描器 (Secret Leak Scanner)

[English](README.md) | **简体中文**

一个小巧的 Python 命令行工具，用来找出代码仓库里**不小心提交的 API key、token、密码和私钥**。
两种技术叠加：

1. **正则规则**：匹配有固定格式的密钥（AWS、GitHub、GitLab、Slack、Stripe、Google、
   OpenAI、Anthropic、JWT、私钥文件头、URL 里的 `user:password@`）。
2. **香农熵**：抓没有固定格式的秘密，包括赋给 `password` / `api_key` / `token` 这类变量名的值，
   以及看起来像随机生成的长字符串。

可以扫描目录，也可以只扫描即将提交的行（做成 **git pre-commit hook**），或者扫描整个 git 历史。

只用标准库，不需要 `pip install`。需要 Python 3.8+ 和 git。

## 用法

```bash
python3 secret_scan.py scan .                 # 扫描工作区
python3 secret_scan.py scan src config.yml    # 指定目录/文件
python3 secret_scan.py scan . --json          # 机器可读的输出（秘密仍然打码）
python3 secret_scan.py staged                 # 只扫描 git add 之后新增的行
python3 secret_scan.py history                # 扫描 git 历史里新增过的每一行
python3 secret_scan.py history --all --max-count 500

python3 secret_scan.py install-hook           # 每次 commit 前自动运行 staged

python3 -m unittest -v                        # 离线测试
```

输出示例（演示里的值全是随机生成的）：

```
[!] .env:1  secret-assignment  L8dK…(28 字符)  fp:0e98dcc7ddce3a3a
    疑似硬编码秘密（STRIPE_TOKEN）
[!] app/client.js:1  high-entropy-string  xgJT…(40 字符)  fp:1ed3f93b37356efe
    高熵字符串 (熵 4.92)
[!] app/settings.py:2  aws-access-key-id  AKIA…(20 字符)  fp:c29a443c4d869a29
    AWS Access Key ID
[!] app/settings.py:3  url-credentials  pfJB…(12 字符)  fp:c819b71a24f270f1
    URL 里的明文密码 (scheme://user:pass@host)
⚠️  发现 4 处疑似密钥泄露。
```

**秘密一律打码**（只显示前 4 个字符和长度），扫描器自己的输出不会把秘密再泄露到终端日志或
CI 日志里。`--show-secrets` 可以关闭打码。

| 退出码 | 含义 |
|---|---|
| `0` | 没发现 |
| `1` | 发现疑似秘密（pre-commit hook 会阻止这次提交） |
| `2` | 出错（路径不存在、不是 git 仓库等） |

## 工作原理

```
 文件 / 暂存区 diff / git log -p
               │
               ▼
 ┌─ 1. 格式规则 ─────────────┐   AKIA…、ghp_…、xoxb-…、sk_live_…、AIza…、
 │   可信度高                │   BEGIN … PRIVATE KEY、eyJ….eyJ….…、://user:pass@
 └───────────┬───────────────┘
             ▼  （已被匹配的片段后面不再检查 → 不会重复报告）
 ┌─ 2. 敏感变量名 = 值 ──────┐   password = "…"、"api_key": "…"、TOKEN=…（.env/yaml/ini）
 │   熵 ≥ 3.0 才报           │   过滤占位符、读环境变量、普通单词
 └───────────┬───────────────┘
             ▼
 ┌─ 3. 任意引号里的字符串 ───┐   ≥ 20 个 [A-Za-z0-9+/=_-] 字符，大写+小写+数字都有，
 │   熵 ≥ 4.5 才报           │   ≤ 200 个字符
 └───────────┬───────────────┘
             ▼
   allowlist（行内注释、.secretsignore） →  打码报告 + 退出码
```

### 香农熵

对字符串 *s*，H(s) = −Σ p(c) · log₂ p(c)，对每个不同的字符 *c* 求和，p(c) 是 *c* 出现的频率。
它衡量「每个字符平均带来多少比特的意外」：

| 字符串 | H（比特/字符） |
|---|---|
| `aaaaaaaa` | 0 |
| `hello_world_this_is_text` | ≈ 3.4 |
| 40 个字符的随机 base64 密钥 | ≈ 4.9–5.3 |

机器生成的密钥是随机的，所以熵高；单词和变量名的熵低。长度为 *n* 的字符串，熵最多是
log₂ *n*，所以熵规则同时要求最小长度：太短的字符串不可能得到高分。

### 减少误报
只看熵会非常吵，所以每一层都有过滤，阈值是拿一个很大的 `site-packages` 目录实测调出来的：
- **跳过占位符**：`${DB_PASS}`、`<YOUR_API_KEY>`、`changeme`、`example`、`xxxx`、
  `os.environ[...]`、`process.env...`、f-string 里的 `{var}`。
- **跳过「描述秘密但本身不是秘密」的变量名**：`token_type`、`auth_method`、
  `password_field`、`api_key_header`……
- 熵规则不报这些：带空格的值（句子）、纯字母标识符（`privateKeyUsagePeriod`）、字母表常量
  （`ABCDEFGH…0123…`）、小写十六进制（git SHA、校验和）、超过 200 个字符的字符串（内嵌图片、证书）。
- 不带引号的 `KEY=value` 只在配置文件里检查（`.env*`、`.ini`、`.yaml`、`.toml`、`.properties`
  等），代码里的 `password = get_password()` 不会被当成秘密。
- 自动跳过：`.git`、`node_modules`、虚拟环境、构建产物、二进制文件（前 8 KiB 里有 NUL 字节）、
  超过 1 MiB 的文件（`--max-size`）、锁文件（`package-lock.json`、`poetry.lock`、`go.sum`
  等，里面全是 integrity 哈希）。

### 速度
每个正则对**整个文件只跑一次**，而不是每行跑一次，这样循环都在 Python 的 C 正则引擎里；
再用二分查找把匹配位置换算回行号。每条规则都以字面量开头（`AKIA`、`ghp_`、`://`……），
正则引擎可以直接跳到候选位置。敏感变量名则是把文本整体转一次小写，而不是用更慢的忽略大小写正则。
实测约 7,600 个文件、260 万行，大约 5 秒。

## Allowlist（标记误报）

1. **行内**：在同一行的注释里写 `secret-scan: allow`。
   ```python
   TEST_KEY = "…假的值…"  # secret-scan: allow
   ```
2. **`.secretsignore`**，放在扫描根目录 / 仓库根目录（或用 `--ignore-file` 指定）：
   ```
   # 路径 glob：跳过整个文件或目录
   tests/fixtures/
   *.snap
   # 单个发现：用报告里打印的指纹
   fp:1ed3f93b37356efe
   ```

指纹是 `sha256(规则名 + ":" + 秘密)` 的前 16 个十六进制字符：能唯一标识这个值，但不用把值本身
写进仓库。它不依赖文件路径和行号，代码挪了位置也照样有效。

## Pre-commit hook

```bash
cd 你的仓库
python3 /path/to/secret_scan.py install-hook
```

它会写入 `.git/hooks/pre-commit`（会遵循 `core.hooksPath` 配置），内容是运行
`secret_scan.py staged`。如果已经有一个不是它装的 hook，除非加 `--force`，否则不会覆盖。

`staged` 解析 `git diff --cached -U0`，**只扫描新增的行**：已经处理过的旧问题不会挡住以后的每次
提交，报告的行号也是新文件里的行号。

## 如果真的泄露了

删掉那一行再提交一次**是不够的**：秘密还在 git 历史里（`history` 找的正是这种），在每一份 clone
和 fork 里，可能还在 CI 日志里。按顺序做：

1. **先到服务商那里吊销 / 轮换密钥。** 默认它已经被复制走了：机器人几分钟内就会扫到 GitHub 上的公开推送。
2. 然后从代码里删掉，改成从环境变量或密钥管理服务读取。
3. 可以再改写历史（`git filter-repo`、BFG）并强制推送。这能让以后的 clone 里不再有它，
   但不会让一个已经泄露的密钥重新变安全，也删不掉别人已经拿到的副本。

## 局限
- **这是启发式，不是证明。** 会有一些误报（所以有 allowlist），也会漏报：低熵的弱密码（比如
  `summer2024`）、被字符串拼接拆开的秘密、经过 base64 / hex 等编码的秘密都会漏掉。
- **不做有效性验证。** 不会调用服务商 API 去检查密钥是否还有效。TruffleHog 这类工具会这么做，
  但这意味着要把秘密发到网络上。
- 规则只覆盖常见服务商。可以往 `RULES` 里追加自己的规则。
- 私钥只靠 `BEGIN … PRIVATE KEY` 这一行文件头识别。
- 纯十六进制字符串不做熵检测（真实代码里哈希太多），所以纯 hex 的 token 只有赋给敏感变量名时才能被发现。
- `git commit --no-verify` 会跳过客户端 hook。要强制执行，还应该在 CI 里跑 `scan` 或 `history`，
  并打开 GitHub 的 push protection。
- `history` 会把整个 `git log -p` 输出读进内存，很大的仓库建议加 `--max-count`。

## 文件
- `secret_scan.py`：命令行工具（规则 → 熵 → allowlist → 扫描目标 → 报告 → hook）
- `test_secret_scan.py`：离线测试（规则、熵过滤、allowlist、打码、在临时 git 仓库里测
  staged/history/hook，以及「扫描器自己的仓库是干净的」）。**所有假密钥都在运行时生成**，
  源码里没有任何像真密钥的字符串，推到 GitHub 不会触发 push protection。

## 参考
- Shannon, "A Mathematical Theory of Communication" (1948)
- OWASP Secrets Management Cheat Sheet:
  https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html
- GitHub secret scanning:
  https://docs.github.com/en/code-security/secret-scanning
- 同类工具：[gitleaks](https://github.com/gitleaks/gitleaks)、
  [TruffleHog](https://github.com/trufflesecurity/trufflehog)、
  [detect-secrets](https://github.com/Yelp/detect-secrets)
