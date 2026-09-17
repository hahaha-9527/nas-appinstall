#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""页面 JS 体检：按 Python **运行时**的真实输出检查内嵌脚本。

为什么需要它
------------
`tpk_installer.py` 里 `PAGE` 是**非 raw** 的三引号字符串，所以源码中写的 `\\'`
在运行时只剩 `'`、写的 `\\\\'` 才输出 `\\'`。一处少写一个反斜杠，输出的 JS 就变成
`onclick="reinstall(''+p.code+'',this)"` —— 相邻字符串字面量 → **整个 <script> 语法错误**
→ 浏览器里一行 JS 都不执行：登录卡片不出现、列表永远停在「加载中」，
而服务端接口用 curl/python 测全是好的。**只有真浏览器才看得见**。

本脚本因此不走"读源码文本"的路子，而是把 PAGE 这个字面量交给 `ast.literal_eval`
求值 —— 得到与运行时**逐字节相同**的 HTML —— 再检查：

1. 内嵌 JS 能否通过 `node --check`（语法）
2. JS 里 `getElementById('x')` 是否都存在 `id="x"`
3. 内联 `onclick="fn(...)"` 调用的函数是否都定义过（静态 + 脚本动态生成，两种都查）
4. 内联 `onclick` 里有没有"被吃掉反斜杠"留下的 `(''` / `'')` 痕迹
5. 是否含内联事件里未转义的双引号
6. `--live` 模式下页面里有没有残留 `__VERSION__` 占位符（旧文件不注入）

用法::

    python tools/check_page.py                      # 检查源码里的 PAGE
    python tools/check_page.py --live http://127.0.0.1:8978
                                                    # 检查**线上实际下发**的页面
    python tools/check_page.py app/tpk_installer.py  # 指定源文件

两种模式都要跑：源码通过不代表线上是对的（部署了旧文件、或改完忘了重启容器，
表现和"代码写错"一模一样）。退出码 0 = 通过，1 = 有问题。
"""
import ast
import io
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_SRC = os.path.join(os.path.dirname(HERE), "app", "tpk_installer.py")

NODE_CANDIDATES = [
    shutil.which("node"),
    r"C:\Program Files\nodejs\node.exe",
    os.path.expanduser(r"~\.workbuddy\binaries\node\versions\22.22.2-3\node.exe"),
]


def load_page(src_path):
    """把 PAGE 字面量求值成运行时字符串（关键：复现 Python 的转义处理）。"""
    text = io.open(src_path, encoding="utf-8", newline="").read()
    m = re.search(r'^PAGE\s*=\s*("""[\s\S]*?""")', text, re.M)
    if not m:
        raise SystemExit("没找到 PAGE = \"\"\"...\"\"\" 字面量")
    return ast.literal_eval(m.group(1))


def load_live(url):
    with urllib.request.urlopen(url, timeout=15) as r:
        return r.read().decode("utf-8", "replace")


def find_node():
    for c in NODE_CANDIDATES:
        if c and os.path.isfile(c):
            return c
    return None


def check():
    args = sys.argv[1:]
    if "--live" in args:
        i = args.index("--live")
        url = args[i + 1] if len(args) > i + 1 else "http://127.0.0.1:8978"
        print("检查线上页面:", url)
        html = load_live(url)
        label = "LIVE"
    else:
        src = [a for a in args if not a.startswith("-")]
        src = src[0] if src else DEFAULT_SRC
        print("检查:", src)
        html = load_page(src)
        label = "SRC"
    print("  [%s] 页面长度: %d 字符" % (label, len(html)))

    bad = 0

    scripts = re.findall(r"<script[^>]*>([\s\S]*?)</script>", html)
    if not scripts:
        print("  !! 页面里没有 <script>")
        return 1
    js = "\n".join(scripts)
    print("  script 块: %d 个, JS %d 字符" % (len(scripts), len(js)))

    # 0) 占位符残留：只在 --live 判 —— 源码里的 PAGE 字面量本来就带占位符，
    #    但线上实际下发的页面若还带着它，说明跑的是不注入的旧文件。
    if label == "LIVE":
        leftover = [x for x in ("__FAVB64__", "__VERSION__") if x in html]
        if leftover:
            print("  !! 线上页面残留占位符: %s（说明部署的是不注入的旧文件）"
                  % ", ".join(leftover))
            bad += 1
        else:
            print("  OK  占位符已全部注入（__FAVB64__ / __VERSION__）")

    # 4) 被吃掉反斜杠的痕迹（先查，报错更直观）
    for i, line in enumerate(html.split("\n"), 1):
        if re.search(r"onclick=\"[^\"]*\(\'\'", line) or re.search(r"onclick=\"[^\"]*\'\'\)", line):
            print("  !! [HTML:%d] onclick 里出现空的 '' —— 多半是源码 \\' 被 Python 吃掉了" % i)
            print("         %s" % line.strip()[:120])
            bad += 1
        if re.search(r"onclick=\"[^\"]*\"[a-zA-Z]", line):
            print("  !! [HTML:%d] onclick 属性里嵌了未转义的双引号" % i)
            print("         %s" % line.strip()[:120])
            bad += 1

    # 1) node --check
    node = find_node()
    if not node:
        print("  ?? 找不到 node，跳过语法检查（强烈建议装 node 后再跑）")
    else:
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "page.js")
            io.open(p, "w", encoding="utf-8", newline="\n").write(js)
            r = subprocess.run([node, "--check", p], capture_output=True, text=True)
            if r.returncode == 0:
                print("  OK  node --check 通过（无语法错误）")
            else:
                print("  !! node --check 失败：")
                for ln in (r.stderr or "").strip().split("\n")[:14]:
                    print("        " + ln)
                bad += 1

    # 2) getElementById 与 id=" 对照
    ids = set(re.findall(r'id="([^"]+)"', html))
    used = set(re.findall(r"getElementById\('([^']+)'\)", js))
    missing = sorted(used - ids)
    if missing:
        print("  !! JS 引用了页面上不存在的 id: %s" % ", ".join(missing))
        bad += 1
    else:
        print("  OK  getElementById 引用齐全（%d 个）" % len(used))

    # 3) 内联 onclick 调用的函数是否定义
    #    必须在**整个页面**上找，不能只找 <script> 内容：静态写法
    #    （写在 HTML 标签上的 onclick="logout()"）不在 <script> 里，
    #    只搜 script 会漏掉一半 —— 本页 6 个 handler 实际只查到 3 个。
    called = set(re.findall(r'onclick="([A-Za-z_$][\w$]*)\(', html))
    defined = set(re.findall(r"function\s+([A-Za-z_$][\w$]*)\s*\(", js))
    defined |= set(re.findall(
        r"(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*function", js))
    undef = sorted(called - defined)
    if undef:
        print("  !! onclick 调用了未定义的函数: %s" % ", ".join(undef))
        bad += 1
    else:
        print("  OK  内联 onclick 函数均已定义（%s）" % (", ".join(sorted(called)) or "无"))

    print("=> %s" % ("全部通过" if bad == 0 else "发现 %d 处问题" % bad))
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(check())
