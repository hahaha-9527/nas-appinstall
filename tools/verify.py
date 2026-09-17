#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""appinstall 安装 / 重启后验证

用法:
    python verify.py http://NAS_IP:8978                 # 只查面板与闸门状态
    python verify.py http://NAS_IP:8978 你的访问口令      # 连自检、应用与包库一起查

口令也可用环境变量给：TPK_PASSWORD=xxx python verify.py http://NAS_IP:8978

检查项:
    1. 面板是否在线（GET /）
    2. 访问闸门状态：待设置 / 待登录 / 已进入
    3. 未登录时 /api/* 是否都被拦住、/files/ 外部下载是否被拒（防裸奔）
    4. 环境自检（/api/selftest）逐项结果与当前路径配置
    5. 已登记的本地上传应用（/api/list）及其应用中心实时状态
    6. 本地包库（/api/pkgs）：应用名、版本、大小、MD5

退出码 0 = 全部正常，1 = 有异常（可直接串进部署脚本）。
"""
import http.cookiejar
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

if len(sys.argv) < 2:
    print(__doc__)
    sys.exit(1)

HOST = sys.argv[1].rstrip("/")
PASSWORD = (sys.argv[2] if len(sys.argv) > 2 else os.environ.get("TPK_PASSWORD") or "").strip()

# 绕过系统代理：局域网地址走代理常常直接失败
opener = urllib.request.build_opener(
    urllib.request.ProxyHandler({}),
    urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
)

bad = 0


def ck(name, ok, detail=""):
    global bad
    if not ok:
        bad += 1
    print("  [%s] %-22s %s" % ("OK" if ok else "NG", name, detail))
    return ok


def get(path, want_json=True):
    req = urllib.request.Request(HOST + path)
    with opener.open(req, timeout=15) as r:
        body = r.read()
        return (json.loads(body.decode("utf-8", "replace")) if want_json
                else body.decode("utf-8", "replace")), r.status


def post(path, payload):
    req = urllib.request.Request(HOST + path,
                                 data=json.dumps(payload).encode("utf-8"),
                                 headers={"Content-Type": "application/json"})
    with opener.open(req, timeout=20) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


print("检查:", HOST)

# ---------- 1) 面板 ----------
try:
    html, code = get("/", want_json=False)
    ck("面板在线", code == 200 and "本地应用安装" in html,
       "http=%s %d 字节" % (code, len(html)))
except Exception as exc:
    ck("面板在线", False, str(exc))
    print("=> 面板都连不上，后面不用查了")
    sys.exit(1)

# ---------- 2) 闸门状态 ----------
try:
    anon, _ = get("/api/list")
except urllib.error.HTTPError as e:
    anon = {"_http": e.code}
state = ("pending" if anon.get("needSetup") else
         "login" if anon.get("needLogin") else "open")
if state == "pending":
    ck("访问闸门", True, "待设置 —— 打开 %s/ 由第一个访问者设置口令" % HOST)
    print("=> 还没设口令，跳过需要登录的检查")
    sys.exit(0)
if state == "login":
    ck("访问闸门", True, "已启用（未登录读不到数据）")
else:
    ck("访问闸门", False, "!! /api/* 未登录就能读 —— 闸门没生效，8978 处于裸奔状态")
    print("=> 闸门失效，请检查部署")
    sys.exit(1)

# ---------- 3) 未登录时的拦截面 ----------
for p in ("/api/pkgs", "/api/selftest"):
    try:
        d, _ = get(p)
        ck("未登录拦截 " + p, bool(d.get("needLogin")), "needLogin=%s" % d.get("needLogin"))
    except urllib.error.HTTPError as e:
        ck("未登录拦截 " + p, e.code in (401, 403), "http=%d" % e.code)
# /files/ 的判定是 `if not (回环 or 已登录)`，回环是"有意放行"（应用中心从这条拉包）。
# 所以同一个探针请求，从回环发和从局域网发，结果不同 —— 必须分开解释。
_probe = "__verify_probe__.tpk"
_is_loopback_target = urllib.parse.urlsplit(HOST).hostname in ("127.0.0.1", "localhost", "::1")
try:
    get("/files/" + _probe, want_json=False)
    ck("/files/ 外部下载受保护", False, "!! 竟然能直接下载安装包")
except urllib.error.HTTPError as e:
    if _is_loopback_target:
        if e.code == 404:
            ck("/files/ 加装包下载", True,
               "本机回环来源（该路径本就放行，供应用中心拉包）；"
               "外部拦截请从局域网另一台机器再跑一次本脚本")
        elif e.code in (401, 403):
            ck("/files/ 加装包下载", True,
               "本机回环来源也被拦了（HTTP %d）—— 说明回环放行失效，"
               "应用中心安装会静默失败，需检查 _is_loopback()" % e.code)
        else:
            ck("/files/ 加装包下载", False, "意外状态 http=%d" % e.code)
    else:
        if e.code in (401, 403):
            ck("/files/ 外部下载受保护", True, "HTTP %d（外部下载已拦截）" % e.code)
        elif e.code == 404:
            ck("/files/ 外部下载受保护", False,
               "HTTP 404 —— 鉴权没拦在文件检查之前，外部来源能探出包库有哪些包")
        else:
            ck("/files/ 外部下载受保护", False, "意外状态 http=%d" % e.code)
except Exception as exc:
    ck("/files/ 外部下载受保护", True, "（%s）" % exc)

# ---------- 登录 ----------
if not PASSWORD:
    print("=> 未提供口令，跳过自检 / 应用 / 包库检查")
    print("=> %s" % ("全部通过" if bad == 0 else "发现 %d 处问题" % bad))
    sys.exit(1 if bad else 0)
try:
    r = post("/api/login", {"password": PASSWORD})
except Exception as exc:
    ck("登录", False, str(exc))
    sys.exit(1)
if not r.get("ok"):
    ck("登录", False, r.get("error") or "口令不对")
    print("=> 口令不对：口令按 PBKDF2 存储，找不回来，只能删掉数据目录下的 "
          ".auth.json 后重启容器回到「设置访问口令」")
    sys.exit(1)
ck("登录", True, "已取得会话")

# ---------- 4) 环境自检 ----------
try:
    st, _ = get("/api/selftest")
    print("  -- 环境自检 --")
    for it in st.get("items") or []:
        print("     [%s] %-14s %s" % ("OK" if it.get("ok") else "NG",
                                      it.get("name"), (it.get("detail") or "")[:72]))
    ck("自检整体", bool(st.get("ok")))
    for k, v in (st.get("path") or {}).items():
        print("     %-14s %s" % (k, v))
except Exception as exc:
    ck("环境自检", False, str(exc))

# ---------- 5) 应用 ----------
try:
    al, _ = get("/api/list")
    apps = al.get("apps") or []
    print("  -- 本地上传的应用（%d 个）--" % len(apps))
    for a in apps:
        print("     %-12s v%-10s %-13s 端口=%s" % (a.get("code"), a.get("version"),
                                                   a.get("state"), a.get("port")))
    ck("应用列表可读", True, "口令来源=%s" % (al.get("authSource") or "?"))
except Exception as exc:
    ck("应用列表可读", False, str(exc))

# ---------- 6) 包库 ----------
try:
    pk, _ = get("/api/pkgs")
    pkgs = pk.get("pkgs") or []
    print("  -- 本地包库（%d 个）--" % len(pkgs))
    for p in pkgs:
        print("     %-12s v%-10s %7dB  %s  md5=%s" % (
            p.get("code"), p.get("version"), p.get("size"),
            p.get("mtime"), (p.get("md5") or "")[:12]))
    ck("包库可读", True)
except Exception as exc:
    ck("包库可读", False, str(exc))

print("=> %s" % ("全部通过" if bad == 0 else "发现 %d 处问题" % bad))
sys.exit(1 if bad else 0)
