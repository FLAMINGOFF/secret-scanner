"""离线单元测试。运行: python3 -m unittest -v

注意：测试用的「假密钥」全部在运行时随机拼出来，源码里没有任何像真密钥的字符串，
所以把这个仓库推到 GitHub 不会触发 push protection，扫描器扫自己也应该是干净的。
"""
import contextlib
import io
import json
import os
import random
import shutil
import string
import subprocess
import tempfile
import unittest

import secret_scan as ss

RNG = random.Random(1234)
UP, LOW, DIG = string.ascii_uppercase, string.ascii_lowercase, string.digits


def rand(n, alphabet=UP + LOW + DIG):
    return "".join(RNG.choice(alphabet) for _ in range(n))


def fake_aws_id():
    return "AK" + "IA" + rand(16, UP + DIG)


def fake_github():
    return "gh" + "p_" + rand(36)


def fake_google():
    return "AI" + "za" + rand(35)


def fake_private_key_header():
    return "-----BEGIN " + "RSA PRIVATE" + " KEY-----"


def rules(line, **kw):
    return [r[0] for r in ss.scan_line(line, **kw)]


class EntropyTests(unittest.TestCase):
    def test_entropy_values(self):
        self.assertEqual(ss.shannon_entropy(""), 0.0)
        self.assertEqual(ss.shannon_entropy("aaaaaaaa"), 0.0)
        self.assertAlmostEqual(ss.shannon_entropy("abcd"), 2.0)
        self.assertGreater(ss.shannon_entropy(rand(40)), 4.5)
        self.assertLess(ss.shannon_entropy("hello_world_this_is_text"), 3.6)


class LineRuleTests(unittest.TestCase):
    def test_known_formats(self):
        self.assertEqual(rules(f'key = "{fake_aws_id()}"'), ["aws-access-key-id"])
        self.assertEqual(rules(f"TOKEN={fake_github()}"), ["github-token"])
        self.assertEqual(rules(f"const k = '{fake_google()}';"), ["google-api-key"])
        self.assertEqual(rules(fake_private_key_header()), ["private-key"])

    def test_url_credentials(self):
        url = "postgres://admin:" + rand(14) + "@db.internal:5432/app"
        self.assertEqual(rules(url), ["url-credentials"])
        self.assertEqual(rules("postgres://user:${DB_PASS}@localhost/app"), [])

    def test_password_assignment_uses_entropy(self):
        self.assertEqual(rules('db_password = "' + "Tr0ub4dor&" + rand(6) + '"'),
                         ["secret-assignment"])
        # 熵太低、太短、或是占位符/环境变量：不报
        self.assertEqual(rules('password = "aaaaaaaaaaaa"'), [])
        self.assertEqual(rules('password = "abc"'), [])
        self.assertEqual(rules('password = "changeme123"'), [])
        self.assertEqual(rules('api_key = "<YOUR_API_KEY>"'), [])
        self.assertEqual(rules('password = os.environ["DB_PASSWORD"]'), [])

    def test_bare_assignment_only_in_config_files(self):
        line = "API_KEY=" + rand(24)
        self.assertIn("secret-assignment", rules(line, config_file=True, use_entropy=False))
        self.assertEqual(rules(line, config_file=False, use_entropy=False), [])

    def test_high_entropy_string(self):
        self.assertEqual(rules(f'x = "{rand(40)}"'), ["high-entropy-string"])
        self.assertEqual(rules(f'x = "{rand(40)}"', use_entropy=False), [])
        # 普通长文本、纯小写、hex 哈希都不算
        self.assertEqual(rules('msg = "this_is_just_a_long_identifier_name"'), [])
        self.assertEqual(rules(f'sha = "{rand(40, "0123456789abcdef")}"'), [])

    def test_no_double_report(self):
        # 格式规则命中后，同一段文本不再被「赋值」「熵」规则重复报告
        self.assertEqual(rules(f'github_token = "{fake_github()}"'), ["github-token"])

    def test_token_must_start_at_word_boundary(self):
        self.assertEqual(rules("x" + fake_github(), use_entropy=False), [])

    def test_identifiers_and_metadata_are_not_secrets(self):
        self.assertEqual(rules('token_type = "refresh_token"'), [])
        self.assertEqual(rules('auth_method = "private_key_jwt"'), [])
        self.assertEqual(rules('alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij0123456789"'), [])

    def test_multiline_offsets_and_unicode(self):
        # 多行一起扫时行号要对；İ 小写后会变成 2 个字符，不能把位置算错
        lines = ["# İİİ 注释", "x = 1", f'tok = "{fake_github()}"', "password = 'P4ss-" + rand(8) + "'"]
        hits = ss.scan_lines(lines)
        self.assertEqual([(h[0], h[1]) for h in hits], [(2, "github-token"), (3, "secret-assignment")])
        self.assertTrue(hits[1][3].startswith("P4ss-"))

    def test_inline_allow(self):
        self.assertEqual(rules(f'k = "{fake_aws_id()}"  # secret-scan: allow'), [])

    def test_mask_never_reveals_secret(self):
        secret = fake_github()
        self.assertNotIn(secret, ss.mask(secret))
        self.assertTrue(ss.mask(secret).startswith(secret[:4]))


class DirScanTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def write(self, rel, text, mode="w"):
        p = os.path.join(self.tmp, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, mode) as f:
            f.write(text)

    def run_cli(self, *argv, cwd=None):
        out = io.StringIO()
        old = os.getcwd()
        os.chdir(cwd or self.tmp)
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
                code = ss.main(list(argv))
        finally:
            os.chdir(old)
        return code, out.getvalue()

    def test_scan_finds_and_skips(self):
        self.aws = fake_aws_id()
        self.write("app/config.py", f'AWS_KEY = "{self.aws}"\n')
        self.write("node_modules/lib/x.js", f'k="{fake_aws_id()}"\n')   # 默认跳过的目录
        self.write("img.bin", b"\0\0" + fake_aws_id().encode(), mode="wb")  # 二进制
        self.write("package-lock.json", f'"integrity": "sha512-{rand(80)}"\n')
        code, out = self.run_cli("scan", ".")
        self.assertEqual(code, ss.EXIT_FOUND)
        self.assertIn("app/config.py:1", out)
        self.assertNotIn("node_modules", out)
        self.assertNotIn("img.bin", out)
        self.assertNotIn(self.aws, out)          # 输出打码

    def test_clean_repo_exit_zero(self):
        self.write("main.py", 'print("hello")\npassword = input("pw: ")\n')
        code, out = self.run_cli("scan", ".")
        self.assertEqual(code, ss.EXIT_CLEAN, out)

    def test_ignore_file_glob_and_fingerprint(self):
        self.write("tests/fixtures/keys.txt", fake_aws_id() + "\n")
        self.write("src/a.py", f'k = "{fake_github()}"\n')
        code, out = self.run_cli("scan", ".", "--json")
        found = json.loads(out)
        self.assertEqual(len(found), 2)
        fp = next(f["fingerprint"] for f in found if f["path"] == "src/a.py")
        self.write(".secretsignore", f"tests/fixtures/\nfp:{fp}  # 已确认是假的\n")
        code, out = self.run_cli("scan", ".")
        self.assertEqual(code, ss.EXIT_CLEAN, out)

    def test_json_masks_by_default(self):
        secret = fake_github()
        self.write("a.py", f'k = "{secret}"\n')
        _, out = self.run_cli("scan", ".", "--json")
        self.assertNotIn(secret, out)
        _, out = self.run_cli("scan", ".", "--json", "--show-secrets")
        self.assertIn(secret, out)

    def test_missing_path_is_error(self):
        code, _ = self.run_cli("scan", "does-not-exist")
        self.assertEqual(code, ss.EXIT_ERROR)

    def test_scanner_own_repo_is_clean(self):
        here = os.path.dirname(os.path.abspath(__file__))
        code, out = self.run_cli("scan", ".", cwd=here)
        self.assertEqual(code, ss.EXIT_CLEAN, out)


@unittest.skipUnless(shutil.which("git"), "需要 git")
class GitTests(unittest.TestCase):
    def setUp(self):
        self.repo = tempfile.mkdtemp()
        self.git("init", "-q")
        self.git("config", "user.email", "t@example.invalid")
        self.git("config", "user.name", "t")
        self.git("config", "commit.gpgsign", "false")

    def tearDown(self):
        shutil.rmtree(self.repo)

    def git(self, *a):
        return subprocess.run(["git", *a], cwd=self.repo, check=True,
                              capture_output=True, text=True).stdout

    def write(self, rel, text):
        with open(os.path.join(self.repo, rel), "w") as f:
            f.write(text)

    def cli(self, *argv):
        out = io.StringIO()
        old = os.getcwd()
        os.chdir(self.repo)
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
                return ss.main(list(argv)), out.getvalue()
        finally:
            os.chdir(old)

    def test_staged_only_sees_added_lines(self):
        old_secret = fake_aws_id()
        self.write("a.py", f'x = 1\nk = "{old_secret}"  # secret-scan: allow\n')
        self.git("add", "a.py")
        self.git("commit", "-qm", "init")
        code, _ = self.cli("staged")
        self.assertEqual(code, ss.EXIT_CLEAN)          # 暂存区为空

        self.write("a.py", f'x = 1\nk = "{old_secret}"  # secret-scan: allow\ntok = "{fake_github()}"\n')
        self.git("add", "a.py")
        code, out = self.cli("staged")
        self.assertEqual(code, ss.EXIT_FOUND)
        self.assertIn("a.py:3", out)                   # 行号对应新文件
        self.assertNotIn("a.py:2", out)

    def test_history_finds_deleted_secret(self):
        self.write("cfg.env", "API_TOKEN=" + rand(32) + "\n")
        self.git("add", ".")
        self.git("commit", "-qm", "oops")
        os.remove(os.path.join(self.repo, "cfg.env"))
        self.git("add", "-A")
        self.git("commit", "-qm", "remove secret")
        self.assertEqual(self.cli("scan", ".")[0], ss.EXIT_CLEAN)   # 工作区已干净
        code, out = self.cli("history")
        self.assertEqual(code, ss.EXIT_FOUND)                       # 但历史里还在
        self.assertIn("cfg.env:1", out)

    def test_install_hook_blocks_commit(self):
        hook = ss.install_hook(self.repo)
        self.assertTrue(os.access(hook, os.X_OK))
        ss.install_hook(self.repo)                     # 重复安装自己的 hook 没问题
        with open(hook, "w") as f:
            f.write("#!/bin/sh\necho someone else\n")
        with self.assertRaises(RuntimeError):          # 不覆盖别人的 hook
            ss.install_hook(self.repo)
        ss.install_hook(self.repo, force=True)

        self.write("b.py", f'k = "{fake_github()}"\n')
        self.git("add", "b.py")
        r = subprocess.run(["git", "commit", "-qm", "leak"], cwd=self.repo,
                           capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0)           # 被 hook 拦下
        self.assertIn("github-token", r.stdout + r.stderr)


if __name__ == "__main__":
    unittest.main()
