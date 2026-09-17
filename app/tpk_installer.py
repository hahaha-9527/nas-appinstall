# -*- coding: utf-8 -*-
"""铁牛NAS 本地 .tpk 安装器 —— 应用中心手动上传口子
- GET  /                上传页面 (选择 .tpk -> 注册进应用中心 -> 触发官方安装)
- POST /api/upload      multipart: file=<tpk>, location=/volume1
- GET  /api/list        本地上传应用列表 (含应用中心内实时状态)
- POST /api/uninstall   {code}  调官方卸载
- GET  /files/<code>.tpk  供应用商店服务下载 (127.0.0.1)
- GET  /icons/<code>.png  应用图标 (本机备查)
- 图标可发布到 /usr/local/pc/<code>-icon.png（配置 TPK_PUBLIC_BASE 后启用），
  手机App / 远程网页必须用公网地址才能读到，否则按局域网地址处理
端口 8978, 仅依赖标准库。"""
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import socket
import sqlite3
import tarfile
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# ---------- 版本号 ----------
# 改动版本时必须与 config.json 的 version 同步（前缀 v 不算），
# `tie-niu-led/appstore/_build_appinstall.py` 打包时会断言两者一致。
# 展示用的版本串（含 v 前缀，与风扇调速等同风格）。
VERSION = "v1.1.3"

# ---------- 可通过环境变量覆盖的部署参数（默认值 = 铁牛 NAS 的路径） ----------
PORT = int(os.environ.get("TPK_PORT") or 8978)
STORE = os.environ.get("TPK_STORE") or "/userdata/tpk_local"
ICONS = os.path.join(STORE, "icons")
# 对外网页目录：由 NAS 上的 nginx/Apache 把 `<公网地址>/pc/` 映射到该目录。
# 手机App 与远程网页都走外网通道，局域网/回环地址一律读不到，必须用公网地址。
WEBROOT = os.environ.get("TPK_WEBROOT") or "/usr/local/pc"
# 公网前缀：手机 App 与远程网页只能读公网地址，局域网地址会显示白图。
# 默认按铁牛（ZeroNAS）的对外代理填好，开箱即用；换别的机器用环境变量覆盖，
# 例如 TPK_PUBLIC_BASE=https://nas.example.com/pc；显式设为 off 则关闭公网发布。
_pb = os.environ.get("TPK_PUBLIC_BASE")
if _pb is None:
    _pb = "https://tieniu.tieniu-link.com/pc"
elif _pb.strip().lower() in ("off", "none", "0", "-"):
    _pb = ""
PUBLIC_BASE = _pb.rstrip("/")
DB = os.environ.get("TPK_DB") or "/userdata/db/appstore.db"
APPSTORE = (os.environ.get("TPK_APPSTORE_API")
            or "http://127.0.0.1:9004/appstoreApi").rstrip("/")
DEFAULT_LOC = os.environ.get("TPK_DEFAULT_LOC") or "/volume1"

# 应用中心"镜像大小"字段：单位 KiB，显示时按 /1024 当 MB 渲染（官方应用同此约定）。
# 本机基础镜像 python:3.12-slim-bookworm 实测 124,351,708 B；与应用中心其它应用共用同一镜像。
# 需要时可用环境变量 TPK_IMAGE_SIZE_KB 覆盖。
IMAGE_SIZE_KB = int(os.environ.get("TPK_IMAGE_SIZE_KB") or 121437)

os.makedirs(ICONS, exist_ok=True)

# ======================= 访问闸门 =======================
# 为什么必须有：.tpk 里的 cmd/install.sh 是以 root 在宿主机上执行的，
# 所以"能打开这个页面"等价于"能以 root 执行任意命令"。8978 默认绑 0.0.0.0，
# 局域网里任何设备（访客 Wi-Fi 上的手机、被入侵的 IoT）都能拖个包把机器接管。
#
# 公开可访问：/ 页面本身、/favicon.ico、/icons/*（被 <img> 直接引用）
# 需要登录：  /api/* 里除 login/logout 之外的接口
# 回环放行：  /files/*  —— 应用中心是从 127.0.0.1 来拉安装包的，
#                        若一律要求登录，安装会因拉不到包而静默失败
AUTH_FILE = os.path.join(STORE, ".auth.json")
PW_FILE = os.path.join(STORE, "访问口令.txt")
COOKIE_NAME = "tpk_session"
SESSION_TTL = 7 * 24 * 3600          # 登录态有效期（秒）
PBKDF2_ROUNDS = 200000
MIN_PW_LEN = 6                       # 口令最短长度

AUTH = None                          # 启动时由 load_auth() 填充
_auth_lock = threading.Lock()
_fail_count = 0                      # 连续失败次数，用于退避
_fail_after = 0.0


def _hash_pw(password, salt):
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ROUNDS)
    return base64.b64encode(dk).decode()


def _new_auth(plain, secret=None, source="page"):
    salt = secrets.token_bytes(16)
    return {
        "salt": base64.b64encode(salt).decode(),
        "hash": _hash_pw(plain, salt),
        "secret": secret or base64.b64encode(secrets.token_bytes(32)).decode(),
        "created": time.strftime("%Y-%m-%d %H:%M:%S"),
        "source": source,            # "page" = 页面上设的；"env" = TPK_PASSWORD
        "_plain": plain,             # 仅在返回给调用方时临时携带，落盘会被剔除
    }


def _save_auth(rec):
    data = {k: v for k, v in rec.items() if not k.startswith("_")}
    tmp = AUTH_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.chmod(tmp, 0o600)
    os.replace(tmp, AUTH_FILE)


def load_auth():
    """读取口令记录。三种情形：

    1. 已有 .auth.json -> 沿用（TPK_PASSWORD 非空且不同则覆盖）
    2. 无记录，但设了 TPK_PASSWORD -> 以它建立记录
    3. 都没有 -> 返回 None，进入「待设置」状态：由第一个打开页面的人自己设

    第 3 条是给**没有 root 权限的人**留的路。旧版在这里随机生成口令并写进
    /userdata/tpk_local/访问口令.txt，而那是 root:root 600 —— 非 root 用户
    装完读不到那个文件，页面又进不去，等于自己把自己锁在门外。
    """
    rec = None
    if os.path.isfile(AUTH_FILE):
        try:
            with open(AUTH_FILE, "r", encoding="utf-8") as f:
                rec = json.load(f)
        except Exception:
            rec = None
    env_pw = (os.environ.get("TPK_PASSWORD") or "").strip()

    if isinstance(rec, dict) and rec.get("hash") and rec.get("salt"):
        if env_pw:
            try:
                salt = base64.b64decode(rec["salt"])
                if not hmac.compare_digest(_hash_pw(env_pw, salt), rec["hash"]):
                    rec = _new_auth(env_pw, rec.get("secret"), source="env")
                    _save_auth(rec)
                    print("[auth] 环境变量里的口令与已存的不同，已更新")
            except Exception as exc:
                print("[auth] 口令更新失败（沿用原口令）: %s" % exc)
        return rec

    if env_pw:
        rec = _new_auth(env_pw, None, source="env")
        _save_auth(rec)
        print("[auth] 访问口令取自环境变量 TPK_PASSWORD")
        return rec

    print("[auth] 尚未设置访问口令 —— 打开 http://<NAS地址>:%d/ 由第一个访问者设置" % PORT)
    return None


def auth_state():
    """pending = 还没设过口令；set = 已设置。"""
    return "set" if AUTH is not None else "pending"


def set_password(plain):
    """写入新口令（首次设置或修改），返回 (ok, 说明)。

    secret 每次重新生成 —— 所以改口令会立刻作废所有已签发的登录态，
    这正是「改完口令，别的设备要被踢下线」想要的效果。
    """
    global AUTH, _fail_count, _fail_after
    plain = (plain or "").strip()
    if len(plain) < MIN_PW_LEN:
        return False, "口令至少 %d 位" % MIN_PW_LEN
    rec = _new_auth(plain, None, source="page")
    _save_auth(rec)
    with _auth_lock:
        AUTH = rec
        _fail_count, _fail_after = 0, 0.0
    # 旧版本随机生成时留下的明文口令文件，设置成功后没必要再留着
    try:
        if os.path.isfile(PW_FILE):
            os.remove(PW_FILE)
    except Exception:
        pass
    return True, "ok"


def check_password(pw):
    """校验口令。连续失败会递增等待时间，拖慢暴力猜测。"""
    global _fail_count, _fail_after
    if AUTH is None:
        return False
    with _auth_lock:
        delay = min(5.0, 0.4 * (2 ** min(_fail_count, 4))) if _fail_count else 0.0
        since = (time.time() - _fail_after) if _fail_after else 1e9
    if delay and since < delay:
        time.sleep(delay - since)
    try:
        salt = base64.b64decode(AUTH["salt"])
        ok = hmac.compare_digest(_hash_pw(pw or "", salt), AUTH["hash"])
    except Exception:
        ok = False
    with _auth_lock:
        if ok:
            _fail_count, _fail_after = 0, 0.0
        else:
            _fail_count += 1
            _fail_after = time.time()
    return ok


def _sign(payload):
    secret = base64.b64decode(AUTH["secret"])
    return hmac.new(secret, payload.encode(), hashlib.sha256).hexdigest()


def issue_session():
    """签发无状态会话串：v1.<过期时间戳>.<HMAC>"""
    payload = "v1.%d" % (int(time.time()) + SESSION_TTL)
    return "%s.%s" % (payload, _sign(payload))


def verify_session(cookie_val):
    if not cookie_val or AUTH is None:
        return False
    try:
        payload, sig = cookie_val.rsplit(".", 1)
        if not hmac.compare_digest(_sign(payload), sig):
            return False
        return int(payload.split(".")[1]) > time.time()
    except Exception:
        return False


def db_exec(sql, params=()):
    con = sqlite3.connect(DB, timeout=15)
    try:
        con.execute(sql, params)
        con.commit()
    finally:
        con.close()


def db_query(sql, params=()):
    con = sqlite3.connect(DB, timeout=15)
    con.row_factory = sqlite3.Row
    try:
        return [dict(r) for r in con.execute(sql, params).fetchall()]
    finally:
        con.close()


def http_json(url, payload=None, timeout=30):
    data = None if payload is None else json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, method="POST" if payload is not None else "GET")
    if payload is not None:
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def parse_multipart(body, ctype):
    """极简 multipart 解析: 返回 {name: (filename|None, bytes)}"""
    m = re.search(r'boundary="?([^";]+)"?', ctype)
    if not m:
        raise ValueError("缺少 boundary")
    bnd = ("--" + m.group(1)).encode()
    fields = {}
    for part in body.split(bnd):
        part = part.strip(b"\r\n")
        if not part or part == b"--":
            continue
        if b"\r\n\r\n" not in part:
            continue
        head, payload = part.split(b"\r\n\r\n", 1)
        headers = head.decode("utf-8", "replace")
        nm = re.search(r'name="([^"]+)"', headers)
        if not nm:
            continue
        fn = re.search(r'filename="([^"]*)"', headers)
        fields[nm.group(1)] = (fn.group(1) if fn else None, payload)
    return fields


def publish_icon(code, data=None):
    """把图标发布到对外网页目录，返回公网 icon_url；不可用时返回 None（调用方退回局域网地址）。"""
    if not PUBLIC_BASE:
        return None  # 未配置公网前缀：不发布，继续用局域网图标地址
    src = os.path.join(ICONS, code + ".png")
    if data is None:
        if not os.path.isfile(src):
            return None
        with open(src, "rb") as f:
            data = f.read()
    dst = os.path.join(WEBROOT, code + "-icon.png")
    try:
        os.makedirs(WEBROOT, exist_ok=True)
        with open(dst, "wb") as f:
            f.write(data)
        os.chmod(dst, 0o644)
    except Exception:
        return None
    return "%s/%s-icon.png" % (PUBLIC_BASE, code)


def heal_icons():
    """启动自愈：把 ICONS 下所有图标发布到对外目录，
    并把 DB 里还是局域网地址的 icon_url/latest_icon_url 换成公网地址。
    这样早先装的应用不用手工改库。"""
    healed = []
    try:
        names = sorted(n[:-4] for n in os.listdir(ICONS) if n.endswith(".png"))
    except Exception:
        return healed
    for code in names:
        url = publish_icon(code)
        if not url:
            continue
        try:
            rows = db_query("SELECT icon_url FROM appstore_app WHERE code=?", (code,))
        except Exception:
            continue
        for r in rows:
            cur = r.get("icon_url") or ""
            if cur.startswith("http") and "/icons/" in cur:
                db_exec("UPDATE appstore_app SET icon_url=?, latest_icon_url=? WHERE code=?",
                        (url, url, code))
                healed.append(code)
    return healed


def _lan_ip():
    """取本机在局域网里的 IP，用于浏览器访问地址。
    做法是 UDP connect 一个不可路由地址，让内核告诉我们出口网卡是谁 —— connect 只把
    地址记在 socket 上，不会真的发出任何数据包。这里的 10.255.255.255 是个固定常量，
    不是本机地址，也不是配置项。"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.255.255.255", 1))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


TRASH = os.path.join(STORE, "trash")


def app_states():
    """一次取回应用中心里全部应用的状态 {code: state}。"""
    try:
        st = http_json(APPSTORE + "/app/status")
        return {a.get("code"): a.get("state") for a in (st.get("data") or [])}
    except Exception:
        return {}


def app_state(code):
    return app_states().get(code)


def install_registered(code, loc, meta):
    """把已注册的应用交给应用中心安装（若已装则先卸旧再装新）。
    返回 (ok, message)。"""
    cur = app_state(code)
    if cur and cur != "notInstalled":
        try:
            http_json(APPSTORE + "/app/uninstall", {"code": code})
        except Exception:
            pass
        for _ in range(15):
            time.sleep(2)
            if app_state(code) in ("notInstalled", None):
                break
    r = http_json(APPSTORE + "/app/install",
                  {"code": code, "installLocation": loc, "installParams": {}})
    if r.get("code") != 200:
        return False, "应用中心返回: %s" % r.get("message")
    final, waited = None, 0
    while waited < 300:
        time.sleep(4)
        waited += 4
        final = app_state(code)
        if final not in ("installing", "downloading", None):
            break
    if final == "started":
        return True, "%s %s 安装成功（%d KB）" % (meta["name"], meta["version"], meta["size"] // 1024)
    return True, "%s 已注册并触发安装，当前状态: %s（可在应用中心查看进度）" % (meta["name"], final)


def selftest():
    """环境自检：换 NAS 或改过配置后，用来自查哪里不兼容。"""
    items = []

    def add(name, ok, detail):
        items.append({"name": name, "ok": bool(ok), "detail": detail})

    try:
        probe = os.path.join(STORE, ".selftest.tmp")
        with open(probe, "w") as f:
            f.write("x")
        os.remove(probe)
        add("包目录可写", True, STORE)
    except Exception as exc:
        add("包目录可写", False, "%s —— %s" % (STORE, exc))

    need = ["code", "icon_url", "state", "shelf_state", "download_url", "version",
            "latest_icon_url", "latest_version", "package_size", "image_size",
            "latest_image_size", "config", "service_name", "release_date",
            "carousel_img_urls", "latest_carousel_img_urls", "latest_version_content",
            "latest_package_size", "is_shortcut", "documentation"]
    try:
        cols = [r["name"] for r in db_query("PRAGMA table_info(appstore_app)")]
        miss = [c for c in need if c not in cols]
        add("应用中心数据库", not miss,
            DB if not miss else "appstore_app 缺少字段: %s" % ", ".join(miss))
    except Exception as exc:
        add("应用中心数据库", False, "%s —— %s" % (DB, exc))

    try:
        st = http_json(APPSTORE + "/app/status", timeout=8)
        add("应用中心接口", st.get("code") == 200,
            "%s（已登记 %d 个应用）" % (APPSTORE, len(st.get("data") or [])))
    except Exception as exc:
        add("应用中心接口", False, "%s —— %s" % (APPSTORE, exc))

    if not PUBLIC_BASE:
        add("图标公网发布", False,
            "未配置 TPK_PUBLIC_BASE：图标只能走局域网地址，手机 App / 远程网页会显示白图")
    else:
        try:
            os.makedirs(WEBROOT, exist_ok=True)
            add("图标对外目录", os.path.isdir(WEBROOT), "%s  →  %s" % (WEBROOT, PUBLIC_BASE))
        except Exception as exc:
            add("图标对外目录", False, "%s —— %s" % (WEBROOT, exc))

    try:
        with urllib.request.urlopen("http://127.0.0.1:%d/favicon.ico" % PORT, timeout=5) as r:
            add("本机回环访问", r.status == 200,
                "http://127.0.0.1:%d（应用中心就是从这条来拉安装包的）" % PORT)
    except Exception as exc:
        add("本机回环访问", False, "http://127.0.0.1:%d —— %s" % (PORT, exc))

    if AUTH is None:
        add("访问闸门", True,
            "待设置：打开 http://<NAS地址>:%d/ 由第一个访问者设定口令（不需要 root）" % PORT)
    else:
        add("访问闸门", True,
            "已启用；口令来自 %s" % ("环境变量 TPK_PASSWORD"
                                     if (AUTH or {}).get("source") == "env"
                                     else "页面设置（记录在 %s）" % AUTH_FILE))

    return {
        "items": items,
        "ok": all(i["ok"] for i in items),
        "path": {"STORE": STORE, "DB": DB, "APPSTORE": APPSTORE, "WEBROOT": WEBROOT,
                 "PUBLIC_BASE": PUBLIC_BASE or "(未配置)", "DEFAULT_LOC": DEFAULT_LOC,
                 "PORT": PORT, "IMAGE_SIZE_KB": IMAGE_SIZE_KB},
    }


def pkg_meta(path):
    """读包内 config.json，取展示信息。读不出来返回 {}。"""
    try:
        with tarfile.open(path, "r:gz") as tf:
            cfg = None
            for n in ("config.json", "./config.json"):
                try:
                    cfg = json.loads(tf.extractfile(n).read().decode("utf-8", "replace"))
                    break
                except KeyError:
                    continue
            if not cfg:
                return {}
        i18n = cfg.get("i18n") or [{}]
        return {
            "name": i18n[0].get("name") or cfg.get("serviceName") or "",
            "version": str((cfg.get("version") or {}).get("version") or ""),
            "appId": str(cfg.get("appId") or ""),
            "port": str(((cfg.get("accessCtrl") or {}).get("urlAppAccesses")
                         or [{}])[0].get("port", "")),
        }
    except Exception:
        return {}


def list_pkgs():
    """扫描 STORE 下留存的 .tpk（含已卸载/未注册的），带上应用中心里的实时状态。"""
    out = []
    try:
        names = sorted(n for n in os.listdir(STORE)
                       if n.endswith(".tpk") and not n.startswith("_"))
    except Exception:
        return out
    states = app_states()
    for fn in names:
        p = os.path.join(STORE, fn)
        try:
            stt = os.stat(p)
            h = hashlib.md5()
            with open(p, "rb") as f:
                for chunk in iter(lambda: f.read(1 << 20), b""):
                    h.update(chunk)
            md5 = h.hexdigest()
        except Exception:
            continue
        code = fn[:-4]
        m = pkg_meta(p)
        out.append({
            "code": code, "file": fn, "size": stt.st_size, "md5": md5,
            "mtime": time.strftime("%Y-%m-%d %H:%M", time.localtime(stt.st_mtime)),
            "name": m.get("name") or code, "version": m.get("version") or "-",
            "appId": m.get("appId") or "", "port": m.get("port") or "",
            "state": states.get(code),
        })
    return out


def register_tpk(path, host_hdr):
    """解析 tpk, 落盘, 注册 DB。返回 (code, meta)"""
    with tarfile.open(path, "r:gz") as tf:
        cfg_f = None
        for n in ("config.json", "./config.json"):
            try:
                cfg_f = tf.extractfile(n)
                break
            except KeyError:
                continue
        if cfg_f is None:
            raise ValueError("包内缺少 config.json")
        cfg = json.loads(cfg_f.read().decode("utf-8", "replace"))
        icon_data = None
        for n in ("icon.png", "./icon.png"):
            try:
                icon_data = tf.extractfile(n).read()
                break
            except KeyError:
                continue

    app_id = str(cfg.get("appId") or "")
    code = re.sub(r"[^a-z0-9_-]", "", app_id.split(".")[-1].lower())
    if not code:
        code = re.sub(r"[^a-z0-9_-]", "", str(cfg.get("serviceName", "")).lower()) or "app"
    version = str((cfg.get("version") or {}).get("version") or "1.0.0")
    service_name = str(cfg.get("serviceName") or code)
    cfg_text = json.dumps(cfg, ensure_ascii=False)

    dst_tpk = os.path.join(STORE, code + ".tpk")
    with open(path, "rb") as a:
        blob = a.read()
    with open(dst_tpk, "wb") as b:
        b.write(blob)

    if icon_data:
        with open(os.path.join(ICONS, code + ".png"), "wb") as f:
            f.write(icon_data)
    # 同步发布一份到对外网页目录，拿公网图标地址
    public_icon = publish_icon(code, icon_data) if icon_data else publish_icon(code)

    host = (host_hdr or "").strip()
    if not host or host.split(":")[0] in ("127.0.0.1", "localhost", "0.0.0.0"):
        host = "%s:%d" % (_lan_ip(), PORT)  # 浏览器要能访问, 回环地址一律换网卡 IP
    dl_url = "http://127.0.0.1:%d/files/%s.tpk" % (PORT, code)
    lan_icon_url = "http://%s/icons/%s.png" % (host, code)
    # 手机App / 远程网页只有公网地址能加载；发布失败才退回局域网地址
    icon_url = public_icon or lan_icon_url
    today = time.strftime("%Y-%m-%d")
    size = os.path.getsize(dst_tpk)

    db_exec(
        """INSERT INTO appstore_app
           (code, icon_url, state, shelf_state, service_name, type, config,
            licence_agreement_link, source_code_link, install_location,
            download_url, download_progress, package_size, carousel_img_urls,
            version, release_date, sort, need_update,
            latest_config, latest_carousel_img_urls, latest_icon_url,
            latest_version, latest_release_date, latest_version_content,
            latest_package_size, image_size, latest_image_size,
            is_shortcut, documentation)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
           ON CONFLICT(code) DO UPDATE SET
             icon_url=excluded.icon_url, service_name=excluded.service_name,
             type=1, config=excluded.config, download_url=excluded.download_url,
             package_size=excluded.package_size, version=excluded.version,
             release_date=excluded.release_date, shelf_state=1, need_update=0,
             latest_config=excluded.latest_config,
             latest_icon_url=excluded.latest_icon_url,
             latest_version=excluded.latest_version,
             latest_release_date=excluded.latest_release_date,
             latest_version_content=excluded.latest_version_content,
             latest_package_size=excluded.latest_package_size,
             image_size=excluded.image_size,
             latest_image_size=excluded.latest_image_size,
             update_time=CURRENT_TIMESTAMP""",
        (code, icon_url, "notInstalled", 1, service_name, 1, cfg_text,
         "", "", "", dl_url, 0, size, "", version, today, 999, 0,
         cfg_text, "", icon_url, version, today, "", size, IMAGE_SIZE_KB, IMAGE_SIZE_KB, 1, ""))
    try:
        db_exec("INSERT OR IGNORE INTO appstore_app_tag_relate(code, tag_code) VALUES (?, 'utilities')", (code,))
    except Exception:
        pass
    return code, {"name": (cfg.get("i18n") or [{}])[0].get("name", code), "version": version, "size": size}


FAVICON_B64 = "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"

PAGE = """<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>本地应用安装</title><link rel="icon" type="image/png" href="data:image/png;base64,__FAVB64__"><style>
*{box-sizing:border-box;margin:0}
body{background:#f4f6fb;color:#1c2333;font:14px/1.6 "Segoe UI","Microsoft YaHei",sans-serif;padding:32px 16px}
.wrap{max-width:760px;margin:0 auto}
h1{font-size:20px;margin-bottom:4px}
p.sub{color:#6b7590;margin-bottom:22px;font-size:13px}
.card{background:#fff;border:1px solid #e3e8f2;border-radius:14px;padding:20px;margin-bottom:16px}
.card h2{font-size:15px;margin-bottom:12px}
.drop{position:relative;border:2px dashed #c4cde0;border-radius:12px;padding:28px;text-align:center;color:#6b7590;cursor:pointer;transition:.2s}
.drop.hover{border-color:#3b82f6;background:#f0f6ff}
.drop b{color:#1c2333}
/* 文件选择框铺满整块区域：点哪都是直接点 input 本体。
   不要用 display:none + JS .click() —— 移动端浏览器与应用内 WebView
   会拦掉对隐藏 file input 的程序化点击，表现就是"点了没反应"。 */
.fileinp{position:absolute;inset:0;width:100%;height:100%;opacity:0;cursor:pointer;font-size:16px}
.row{display:flex;gap:10px;align-items:center;margin-top:14px;flex-wrap:wrap}
input[type=text],input[type=password]{flex:1;min-width:180px;padding:8px 10px;border:1px solid #dbe1ee;border-radius:9px;font-size:13px}
button{background:#3b82f6;color:#fff;border:0;border-radius:9px;padding:9px 18px;font-size:14px;cursor:pointer}
button:disabled{opacity:.5;cursor:wait}
button.ghost{background:#fff;color:#c0392b;border:1px solid #f0c7c0;padding:5px 12px;font-size:12.5px}
.msg{margin-top:12px;padding:10px 12px;border-radius:9px;font-size:13px;display:none}
.msg.ok{display:block;background:#e9f9ef;color:#187741}
.msg.err{display:block;background:#fdeeee;color:#c0392b}
.msg.busy{display:block;background:#fff7e6;color:#9a6b00}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:8px 6px;border-bottom:1px solid #eef1f7}
th{color:#6b7590;font-weight:500;font-size:12px}
img.ic{width:34px;height:34px;border-radius:9px;vertical-align:middle;background:#eef1f7}
.st{display:inline-block;padding:1px 9px;border-radius:99px;font-size:12px}
.st.started{background:#e9f9ef;color:#187741}
.st.installing{background:#fff7e6;color:#9a6b00}
.st.notInstalled{background:#eef1f7;color:#6b7590}
.hint{color:#8a93ab;font-size:12px;margin-top:10px;line-height:1.8}
kbd{background:#eef1f7;border-radius:5px;padding:1px 7px;font-size:12px}
h1 .ghost{float:right;font-size:12.5px}
.ftr{text-align:center;color:#8a93ab;font-size:12px;margin:20px 0 26px;letter-spacing:.4px}
.ftr b{color:#3b82f6;font-weight:600}
@media(max-width:640px){
  body{padding:16px 10px;-webkit-text-size-adjust:100%}
  h1{font-size:18px}
  h1 .ghost{float:none;display:block;margin-top:10px;width:100%;padding:10px}
  .ftr{margin:16px 0 20px}
  p.sub{margin-bottom:16px}
  .card{padding:14px;border-radius:12px}
  .card h2{font-size:14.5px}
  .drop{padding:22px 12px}
  /* 触屏输入框小于 16px 会被 iOS 自动放大页面；16px 是安全阈值 */
  input[type=text],input[type=password]{flex:1 1 100%;width:100%;font-size:16px;padding:11px 12px}
  .row{gap:8px}
  .row>button{flex:1 1 100%;width:100%;padding:13px 18px;font-size:15px}
  .row>span{flex:1 1 100%}
  button.ghost{padding:9px 12px;font-size:13px}
  /* 6 列表格在手机上没法横排：改成一行一项的卡片式 */
  table{font-size:14px}
  table thead{display:none}
  table,tbody,tr,td{display:block;width:100%}
  tbody tr{border:1px solid #eef1f7;border-radius:10px;padding:10px 12px;margin-bottom:10px;background:#fff}
  tbody tr:last-child{margin-bottom:0}
  td{border:0;padding:4px 0;display:flex;flex-wrap:wrap;gap:8px;align-items:center}
  td:before{content:attr(data-l);color:#8a93ab;font-size:12px;flex:0 0 58px}
  td:first-child{padding-bottom:8px;border-bottom:1px solid #f2f5fa;margin-bottom:6px}
  td:first-child:before{display:none}
  td[colspan]{justify-content:center}
  td[colspan]:before{display:none}
  td>button.ghost{margin-right:4px}
  img.ic{width:30px;height:30px}
  .hint{font-size:12.5px}
}
</style></head><body><div class="wrap">
<h1>本地应用安装<button class="ghost" id="out" style="display:none" onclick="logout()">退出登录</button></h1>
<p class="sub">官方应用中心只支持在线商店下载；这里提供本地 .tpk 安装包上传入口，装好后的应用会出现在应用中心里，可正常启动/停止/卸载。</p>

<div class="card" id="bootmsg" style="display:none;background:#fff5f5;border-color:#f5c2c0">
  <h2 style="color:#b91c1c">页面脚本没能启动</h2>
  <p class="hint" style="margin-top:0">下面的列表一直停在「加载中」通常就是这个原因。
  先强制刷新（Ctrl / Cmd + Shift + R）；仍不行就换 Chrome / Edge / Safari 打开，
  或检查浏览器有没有禁用 JavaScript。</p>
</div>

<div class="card" id="cardSetup" style="display:none">
  <h2>设置访问口令</h2>
  <p class="hint" style="margin-top:0">这是安装器的第一次使用。这个页面装上去的包会以 <b>root</b> 身份在 NAS 上执行，
  所以先设一个访问口令 —— 之后打开这个页面都要输它，没有口令的人装不了东西。<br>
  口令由你自己定，记得住就行。忘了的话要请有 root 权限的人在 NAS 上删掉
  <kbd>/userdata/tpk_local/.auth.json</kbd> 并重启容器，页面会回到这一步。</p>
  <div class="row">
    <input type="password" id="spw" placeholder="设置口令（至少 6 位）">
    <input type="password" id="spw2" placeholder="再输一次">
    <button id="sbtn">设置并进入</button>
  </div>
  <div class="msg" id="smsg"></div>
  <p class="hint">设好之后，同一网络里的其它设备（访客手机、IoT 设备）即使打开这个页面也装不了包。</p>
</div>

<div class="card" id="cardLogin" style="display:none">
  <h2>需要访问口令</h2>
  <p class="hint" style="margin-top:0">这个页面安装的应用会以 root 身份在 NAS 上跑，所以加了一道口令，
  免得同一网络里的其他设备（访客手机、IoT 设备）随手传包把机器接管。</p>
  <div class="row">
    <input type="password" id="pw" placeholder="访问口令">
    <button id="lbtn">进入</button>
  </div>
  <div class="msg" id="lmsg"></div>
  <p class="hint">登录状态保持 7 天，换浏览器或清缓存后需要重新输一次。<br>
  忘了口令：记录在 <kbd>/userdata/tpk_local/.auth.json</kbd>（只有 root 能读，也读不回明文），
  请有 root 权限的人删掉它并重启容器 <kbd>appinstall-app</kbd>，页面会回到「设置访问口令」。</p>
</div>

<div class="card" id="cardUp">
  <h2>上传安装包</h2>
    <div class="drop" id="drop">
    <span id="droptxt">点击选择 <b>.tpk 安装包</b>，或把文件拖到这里</span>
    <input type="file" id="f" class="fileinp" accept=".tpk">
  </div>
  <p class="hint" id="uphint" style="display:none">手机上传受浏览器限制：<b>点了没反应</b>说明当前页面（或 NAS App 内置页面）不允许选文件，<b>一选文件浏览器就退出</b>说明它处理不了这种安装包 —— 两种情况都请换用电脑浏览器打开本地址上传。手机自带浏览器（Chrome / Safari / Edge）通常可以。</p>
  <div class="row">
    <span style="color:#6b7590;font-size:13px">安装位置</span>
    <input type="text" id="loc" value="/volume1">
    <button id="go" onclick="up()">安装</button>
  </div>
  <div class="msg" id="msg"></div>
  <p class="hint">安装包要求：tar.gz 格式的 .tpk，内含 <kbd>config.json</kbd>（appId/i18n/accessCtrl）与 <kbd>docker-compose.tmpl</kbd>、<kbd>cmd/</kbd> 脚本。安装位置需为存储池路径（如 /volume1）。</p>
</div>

<div class="card" id="cardList">
  <h2>本地上传的应用</h2>
  <table><thead><tr><th>应用</th><th>版本</th><th>状态</th><th></th></tr></thead>
  <tbody id="rows"><tr><td colspan="4" style="color:#8a93ab">加载中…</td></tr></tbody></table>
  <p class="hint">状态列与应用中心实时同步。卸载等同应用中心内卸载。</p>
</div>

<div class="card" id="cardPkg">
  <h2>本地安装包 <span style="color:#8a93ab;font-size:12px;font-weight:400">NAS 上留存的 .tpk，可重装或清理</span></h2>
  <table><thead><tr><th>应用</th><th>版本</th><th>大小</th><th>上传时间</th><th>MD5</th><th></th></tr></thead>
  <tbody id="prows"><tr><td colspan="6" style="color:#8a93ab">加载中…</td></tr></tbody></table>
  <p class="hint">删除会把包移入 <kbd>trash/</kbd> 子目录而不是真删，方便反悔；应用仍在安装或运行中时不允许删。</p>
</div>

<div class="card" id="cardPw">
  <h2>访问口令</h2>
  <p class="hint" style="margin-top:0">当前口令：<span id="pwstate">已启用</span>。
  在这里改口令后，其它设备上的登录会立刻失效（那台机器需要重新输一次新口令）。</p>
  <div class="row">
    <input type="password" id="opw" placeholder="当前口令">
    <input type="password" id="npw" placeholder="新口令（至少 6 位）">
    <button id="pbtn">修改</button>
  </div>
  <div class="msg" id="pmsg"></div>
</div>

<div class="card" id="cardSelf">
  <h2>环境自检 <button class="ghost" style="color:#3b82f6;border-color:#cfe0f7;float:right" onclick="selftest()">开始检查</button></h2>
  <div id="selfout" class="hint" style="margin-top:0">换 NAS 或改过配置后点一下，确认路径、数据库、应用中心接口都正常。</div>
</div>

<script>
var file=null;
var f=document.getElementById('f');
// 手机适配：accept=".tpk" 是非标准扩展名，安卓侧要解析 MIME，
// 部分 WebView 在拉起选择器时会直接崩掉（表现：点了选择文件浏览器闪退）。
// 触屏环境干脆不限制类型，交给服务端校验；桌面保留以便筛文件。
var _touch=('ontouchstart' in window)||/Android|iPhone|iPad|iPod|Mobile/i.test(navigator.userAgent);
if(_touch){f.removeAttribute('accept');
  var _uh=document.getElementById('uphint');if(_uh)_uh.style.display='block';}
f.onchange=function(){ if(f.files.length){ file=f.files[0]; document.getElementById('droptxt').innerHTML='已选择：<b>'+file.name+'</b>（'+Math.round(file.size/1024)+' KB），点击可重新选择'; } };
var drop=document.getElementById('drop');
drop.ondragover=function(e){e.preventDefault();drop.classList.add('hover');};
drop.ondragleave=function(){drop.classList.remove('hover');};
drop.ondrop=function(e){e.preventDefault();drop.classList.remove('hover');
  if(e.dataTransfer.files.length){file=e.dataTransfer.files[0];f.files=e.dataTransfer.files;document.getElementById('droptxt').innerHTML='已选择：<b>'+file.name+'</b>，点击可重新选择';}};
function msg(t,c){var m=document.getElementById('msg');m.className='msg '+c;m.textContent=t;}
var ALL_CARDS=['cardSetup','cardLogin','cardUp','cardList','cardPkg','cardSelf','cardPw'];
var APP_CARDS=['cardUp','cardList','cardPkg','cardSelf','cardPw'];
var _view='';
// 三态切换：待设置 / 待登录 / 已进入。带 tag 去重，免得 5 秒一次的轮询
// 反复抢输入框焦点。
function showOnly(ids,tag){
  if(_view===tag)return false;
  _view=tag;
  ALL_CARDS.forEach(function(x){
    var el=document.getElementById(x); if(el)el.style.display=(ids.indexOf(x)>=0)?'block':'none';
  });
  document.getElementById('out').style.display=(tag==='app')?'inline-block':'none';
  return true;
}
function focusIf(id,on){ if(on){var e=document.getElementById(id); if(e)e.focus();} }
function showSetup(){ focusIf('spw',showOnly(['cardSetup'],'setup')); }
function showLogin(){ focusIf('pw',showOnly(['cardLogin'],'login')); }
function showApp(){ showOnly(APP_CARDS,'app'); }
function setmsg(id,t,c){var m=document.getElementById(id);m.className='msg '+c;m.textContent=t;}
function doLogin(){
  var m='lmsg';
  setmsg(m,'校验中…','busy');
  fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({password:document.getElementById('pw').value})})
   .then(function(r){return r.json()}).then(function(j){
     if(j.ok){location.reload();}
     else{setmsg(m,j.error||'口令不对','err');}
   }).catch(function(e){setmsg(m,'失败：'+e,'err');});
}
function doSetup(){
  var a=document.getElementById('spw').value, b=document.getElementById('spw2').value;
  if(a.length<6){setmsg('smsg','口令至少 6 位','err');return;}
  if(a!==b){setmsg('smsg','两次输入不一致','err');return;}
  setmsg('smsg','设置中…','busy');
  fetch('/api/setup',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({password:a})})
   .then(function(r){return r.json()}).then(function(j){
     if(j.ok){location.reload();}
     else{setmsg('smsg',j.error||'设置失败','err');}
   }).catch(function(e){setmsg('smsg','失败：'+e,'err');});
}
function doPasswd(){
  var o=document.getElementById('opw').value, n=document.getElementById('npw').value;
  if(n.length<6){setmsg('pmsg','新口令至少 6 位','err');return;}
  setmsg('pmsg','修改中…','busy');
  fetch('/api/passwd',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({old:o,password:n})})
   .then(function(r){return r.json()}).then(function(j){
     if(j.ok){setmsg('pmsg',j.message||'已更新','ok');
              document.getElementById('opw').value='';document.getElementById('npw').value='';}
     else{setmsg('pmsg',j.error||'修改失败','err');}
   }).catch(function(e){setmsg('pmsg','失败：'+e,'err');});
}
function logout(){fetch('/api/logout',{method:'POST'}).then(function(){location.reload()});}
// 按钮一律在这里绑定，不写内联 onclick —— 内联 onclick 要嵌进 JS 字符串里，
// 少一个反斜杠就会把整段脚本写崩（v1.1.0 出过这个事故：页面停在全屏「加载中」）。
document.getElementById('lbtn').onclick=doLogin;
document.getElementById('sbtn').onclick=doSetup;
document.getElementById('pbtn').onclick=doPasswd;
document.getElementById('pw').onkeydown=function(e){if(e.key==='Enter')doLogin();};
document.getElementById('spw2').onkeydown=function(e){if(e.key==='Enter')doSetup();};
document.getElementById('npw').onkeydown=function(e){if(e.key==='Enter')doPasswd();};
function loadPkgs(){
  fetch('/api/pkgs').then(function(r){return r.json()}).then(function(j){
    if(j.needLogin||j.needSetup){return;}
    var t='';
    (j.pkgs||[]).forEach(function(p){
      var running=p.state&&p.state!=='notInstalled';
      t+='<tr><td>'+p.name+'<div style="color:#8a93ab;font-size:12px">'+p.file+'</div></td>'+
         '<td data-l="版本">'+p.version+'</td><td data-l="大小">'+Math.round(p.size/1024)+' KB</td>'+
         '<td data-l="上传时间">'+p.mtime+'</td>'+
         '<td data-l="MD5" style="font-family:ui-monospace,Consolas,monospace;font-size:11.5px;color:#8a93ab">'+(p.md5||'').slice(0,8)+'</td>'+
         '<td data-l="操作"><a href="/files/'+p.code+'.tpk" download><button class="ghost" style="color:#3b82f6;border-color:#cfe0f7">下载</button></a> '+
         '<button class="ghost" onclick="reinstall(\\''+p.code+'\\',this)">重装</button> '+
         '<button class="ghost" onclick="delpkg(\\''+p.code+'\\','+(running?1:0)+')">删除</button></td></tr>';
    });
    document.getElementById('prows').innerHTML=t||'<tr><td colspan="6" style="color:#8a93ab">还没有本地安装包</td></tr>';
  });
}
function reinstall(c,btn){
  if(!confirm('用本地包重新安装 '+c+'？会先卸载当前版本。'))return;
  btn.disabled=true;var old=btn.textContent;btn.textContent='安装中…';
  msg('正在重装 '+c+'，大包可能要 1-3 分钟…','busy');
  fetch('/api/pkg/reinstall',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({code:c,location:document.getElementById('loc').value.trim()||'/volume1'})})
   .then(function(r){return r.json()}).then(function(j){
     btn.disabled=false;btn.textContent=old;
     msg(j.ok?j.message:('失败：'+(j.error||'未知错误')),j.ok?'ok':'err');
     load();loadPkgs();
   }).catch(function(e){btn.disabled=false;btn.textContent=old;msg('失败：'+e,'err');});
}
function delpkg(c,running){
  if(running){alert('应用正在安装或运行中，请先在应用中心卸载，再删除本地包。');return;}
  if(!confirm('删除本地包 '+c+'？会移入 trash/ 子目录，不是真删。'))return;
  fetch('/api/pkg/delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({code:c})})
   .then(function(r){return r.json()}).then(function(j){
     if(!j.ok)alert('失败：'+(j.error||'未知错误'));
     loadPkgs();
   });
}
function selftest(){
  var o=document.getElementById('selfout');
  o.innerHTML='检查中…';
  fetch('/api/selftest').then(function(r){return r.json()}).then(function(j){
    if(j.needLogin){return;}
    var t='';
    (j.items||[]).forEach(function(i){
      t+='<div style="margin:7px 0"><span class="st '+(i.ok?'started':'installing')+'">'+
         (i.ok?'正常':'注意')+'</span> <b style="color:#1c2333;font-weight:500">'+i.name+'</b> '+
         '<span style="color:#8a93ab">'+i.detail+'</span></div>';
    });
    var p=j.path||{},ps=[];
    for(var k in p){ps.push(k+' = '+p[k]);}
    t+='<div style="margin-top:14px;color:#8a93ab;font-size:12px;line-height:2">'+ps.join('　·　')+'</div>';
    o.innerHTML=t;
  });
}
function up(){
  if(!file){msg('请先选择 .tpk 文件','err');return;}
  var fd=new FormData();fd.append('file',file);fd.append('location',document.getElementById('loc').value.trim()||'/volume1');
  var btn=document.getElementById('go');btn.disabled=true;
  msg('上传中，随后开始安装（大包可能需要1-3分钟）…','busy');
  fetch('/api/upload',{method:'POST',body:fd}).then(function(r){return r.json()}).then(function(j){
    btn.disabled=false;
    if(j.ok){msg(j.message+'　可在应用中心查看','ok');file=null;f.value='';document.getElementById('droptxt').innerHTML='点击选择 <b>.tpk 安装包</b>，或把文件拖到这里';load();}
    else{msg('失败：'+(j.error||'未知错误'),'err');}
  }).catch(function(e){btn.disabled=false;msg('失败：'+e,'err');});
}
function load(){
  fetch('/api/list').then(function(r){return r.json()}).then(function(j){
    if(j.needSetup){showSetup();return;}
    if(j.needLogin){showLogin();return;}
    showApp();
    var ps=document.getElementById('pwstate');
    if(ps&&j.authState){ps.textContent=(j.authSource==='env'
      ? '由 TPK_PASSWORD 环境变量指定（在这里改动会被下次重启覆盖）'
      : (j.authSource==='page'?'已启用（在页面上设置）':'已启用'));}
    var t='';
    (j.apps||[]).forEach(function(a){
      var st=a.state==='started'?'运行中':(a.state==='installing'?'安装中':(a.state==='stopped'?'已停止':'未安装'));
      t+='<tr><td><img class="ic" src="'+a.icon_url+'"> '+a.name+'</td><td data-l="版本">'+a.version+'</td>'+
         '<td data-l="状态"><span class="st '+a.state+'">'+st+'</span></td>'+
         '<td data-l="操作"><button class="ghost" onclick="unins(\\''+a.code+'\\')">卸载</button></td></tr>';
    });
    document.getElementById('rows').innerHTML=t||'<tr><td colspan="4" style="color:#8a93ab">还没有通过这里安装过应用</td></tr>';
  });
}
function unins(c){
  if(!confirm('确定卸载 '+c+' ?'))return;
  fetch('/api/uninstall',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({code:c})})
   .then(function(r){return r.json()}).then(function(j){load();});
}
load(); loadPkgs(); setInterval(load,5000);
</script>
<script>
// 独立脚本块：万一上面那段整体语法出错（v1.1.0 出过），这一段仍会执行，
// 直接把原因摆到页面上，免得用户只看到一句「加载中」反馈不出信息。
setTimeout(function(){
  function vis(id){var e=document.getElementById(id);return e&&e.style.display!=='none';}
  var rows=document.getElementById('rows');
  if(rows&&vis('cardList')&&!/还没有/.test(rows.textContent)&&/加载中/.test(rows.textContent)
     &&!vis('cardLogin')&&!vis('cardSetup')){
    document.getElementById('bootmsg').style.display='block';
  }
},4000);
</script>
<div class="ftr">© 2026 应用安装 <b>__VERSION__</b> · Crafted by 西了个瓜</div>
</div></body></html>"""


PAGE = PAGE.replace("__FAVB64__", FAVICON_B64).replace("__VERSION__", VERSION)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, ctype, body):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, ok, **kw):
        kw["ok"] = ok
        self._send(200, "application/json; charset=utf-8",
                   json.dumps(kw, ensure_ascii=False).encode("utf-8"))

    # ---- 鉴权辅助 ----
    def _is_loopback(self):
        """请求是否来自本机（应用中心拉包就是走这条）。"""
        try:
            return self.client_address[0] in ("127.0.0.1", "::1", "::ffff:127.0.0.1")
        except Exception:
            return False

    def _cookie(self, name):
        for kv in (self.headers.get("Cookie") or "").split(";"):
            if "=" in kv:
                k, v = kv.split("=", 1)
                if k.strip() == name:
                    return v.strip()
        return ""

    def _authed(self):
        return verify_session(self._cookie(COOKIE_NAME))

    def _need_login(self):
        """未登录时给出提示；返回 True 表示已拦截。
        两种拦截：还没设口令（needSetup）/ 设了但没登录（needLogin），
        前端按这两个字段决定显示「设置口令」还是「登录」卡片。
        这里**不**放行回环来源 —— /api/* 是写操作入口，回环放行只给 /files/
        （应用中心从 127.0.0.1 拉包，不放行会静默打断安装）。"""
        if AUTH is None:
            self._json(False, needSetup=True, error="请先设置访问口令")
            return True
        if self._authed():
            return False
        self._json(False, needLogin=True, error="请先登录")
        return True

    def _set_session(self, val):
        self.send_header("Set-Cookie",
                         "%s=%s; Path=/; Max-Age=%d; HttpOnly; SameSite=Lax"
                         % (COOKIE_NAME, val, SESSION_TTL))

    def _ok_session(self, message):
        """200 + 下发会话 cookie。设置口令/改口令成功后直接把人放进来。"""
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self._set_session(issue_session())
        payload = json.dumps({"ok": True, "message": message},
                             ensure_ascii=False).encode("utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        p = self.path.split("?")[0]
        # /icons/ 与 /favicon.ico 公开（<img> 直接引用，不带 cookie 也得能读）；
        # /api/* 一律要登录 —— 含 /api/list。未登录返回 200 + needLogin=true（不是 401），
        # 前端三处 fetch 都判 j.needLogin 来切登录框；真正返 401 的只有 /files/ 下载守卫
        if p.startswith("/api/") and self._need_login():
            return
        if self.path == "/favicon.ico":
            self._send(200, "image/png", base64.b64decode(FAVICON_B64))
        elif self.path in ("/", "/index.html"):
            self._send(200, "text/html; charset=utf-8", PAGE.encode("utf-8"))
        elif self.path == "/api/selftest":
            try:
                r = selftest()
                # selftest() 里那个 ok 是"整体是否全通过"，直接当响应码用；
                # 不能写成 self._json(True, **r) —— 会和形参 ok 撞名
                self._json(r.pop("ok"), **r)
            except Exception as e:
                self._json(False, error=str(e))
        elif self.path == "/api/pkgs":
            try:
                self._json(True, pkgs=list_pkgs())
            except Exception as e:
                self._json(False, error=str(e))
        elif self.path == "/api/list":
            try:
                rows = db_query(
                    "SELECT code, config, state, version, icon_url, install_location "
                    "FROM appstore_app WHERE download_url LIKE ?", ("%/files/%%.tpk",))
                apps = []
                for r in rows:
                    try:
                        cfg = json.loads(r["config"])
                        name = (cfg.get("i18n") or [{}])[0].get("name", r["code"])
                        port = ((cfg.get("accessCtrl") or {}).get("urlAppAccesses") or [{}])[0].get("port", "")
                    except Exception:
                        name, port = r["code"], ""
                    apps.append({"code": r["code"], "name": name, "version": r["version"],
                                 "state": r["state"], "icon_url": r["icon_url"], "port": port})
                self._json(True, apps=apps, authState=auth_state(),
                           authSource=(AUTH or {}).get("source", ""))
            except Exception as e:
                self._json(False, error=str(e))
        elif self.path.startswith("/files/") and self.path.endswith(".tpk"):
            # 应用中心从回环来拉包 -> 放行；外部来源要登录，防止包被随便下载
            if not (self._is_loopback() or self._authed()):
                return self._send(401, "text/plain; charset=utf-8", "需要登录".encode("utf-8"))
            code = re.sub(r"[^a-z0-9_-]", "", self.path.split("/files/")[1][:-4])
            p = os.path.join(STORE, code + ".tpk")
            if os.path.isfile(p):
                with open(p, "rb") as f:
                    self._send(200, "application/octet-stream", f.read())
            else:
                self._send(404, "text/plain", b"not found")
        elif self.path.startswith("/icons/") and self.path.endswith(".png"):
            code = re.sub(r"[^a-z0-9_-]", "", self.path.split("/icons/")[1][:-4])
            p = os.path.join(ICONS, code + ".png")
            if os.path.isfile(p):
                with open(p, "rb") as f:
                    self._send(200, "image/png", f.read())
            else:
                self._send(404, "text/plain", b"not found")
        else:
            self._send(404, "text/plain", b"not found")

    def do_POST(self):
        try:
            ln = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(ln)
            # 首次设置口令：**只在尚未设置时开放，且不需要登录**。
            # 这是给没有 root 权限的人留的唯一入口 —— 他们读不到 root 的
            # 600 文件，命令行也碰不到，只能从页面上自己设一个。
            # 一旦设置成功，本接口永久关闭（除非删掉 .auth.json）。
            if self.path == "/api/setup":
                if AUTH is not None:
                    return self._json(False, error="口令已经设置过了，请直接登录")
                try:
                    d = json.loads(body.decode("utf-8", "replace") or "{}")
                except Exception:
                    d = {}
                ok, why = set_password(str(d.get("password") or ""))
                if not ok:
                    return self._json(False, error=why)
                return self._ok_session("口令已设置")
            if self.path == "/api/login":
                try:
                    d = json.loads(body.decode("utf-8", "replace") or "{}")
                except Exception:
                    d = {}
                if check_password(str(d.get("password") or "")):
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json; charset=utf-8")
                    self._set_session(issue_session())
                    payload = json.dumps({"ok": True}, ensure_ascii=False).encode("utf-8")
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
                    return
                return self._json(False, error="口令不对")
            if self.path == "/api/logout":
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Set-Cookie", "%s=; Path=/; Max-Age=0" % COOKIE_NAME)
                payload = json.dumps({"ok": True}, ensure_ascii=False).encode("utf-8")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return
            # 其余写接口一律要登录（写操作会以 root 在宿主机上落地）
            if self._need_login():
                return
            if self.path == "/api/passwd":
                try:
                    d = json.loads(body.decode("utf-8", "replace") or "{}")
                except Exception:
                    d = {}
                if not check_password(str(d.get("old") or "")):
                    return self._json(False, error="当前口令不对")
                ok, why = set_password(str(d.get("password") or ""))
                if not ok:
                    return self._json(False, error=why)
                return self._ok_session("口令已更新，其它设备上的登录已失效")
            if self.path == "/api/upload":
                fields = parse_multipart(body, self.headers.get("Content-Type", ""))
                if "file" not in fields:
                    return self._json(False, error="缺少文件字段")
                fn, data = fields["file"]
                if not (fn or "").lower().endswith(".tpk"):
                    return self._json(False, error="请上传 .tpk 文件")
                loc = "location" in fields and fields["location"][1].decode("utf-8", "replace").strip() or DEFAULT_LOC
                tmp = os.path.join(STORE, "_upload.tpk")
                with open(tmp, "wb") as f:
                    f.write(data)
                code, meta = register_tpk(tmp, self.headers.get("Host"))
                ok, message = install_registered(code, loc, meta)
                return self._json(True, message=message) if ok else self._json(False, error=message)
            if self.path == "/api/pkg/reinstall":
                d = json.loads(body.decode("utf-8", "replace") or "{}")
                code = re.sub(r"[^a-z0-9_-]", "", str(d.get("code") or ""))
                src = os.path.join(STORE, code + ".tpk")
                if not code or not os.path.isfile(src):
                    return self._json(False, error="本地没有这个包")
                loc = (str(d.get("location") or "").strip() or DEFAULT_LOC)
                code2, meta = register_tpk(src, self.headers.get("Host"))
                ok, message = install_registered(code2, loc, meta)
                return self._json(True, message=message) if ok else self._json(False, error=message)
            if self.path == "/api/pkg/delete":
                d = json.loads(body.decode("utf-8", "replace") or "{}")
                code = re.sub(r"[^a-z0-9_-]", "", str(d.get("code") or ""))
                src = os.path.join(STORE, code + ".tpk")
                if not code or not os.path.isfile(src):
                    return self._json(False, error="本地没有这个包")
                # 应用还在跑就先别删包，否则想重装时手里就没底包了
                st = app_state(code)
                if st and st != "notInstalled":
                    return self._json(False, error="应用当前状态是 %s，请先在应用中心卸载再删除包" % st)
                os.makedirs(TRASH, exist_ok=True)
                dst = os.path.join(TRASH, "%s.tpk.%s" % (code, time.strftime("%Y%m%d%H%M%S")))
                try:
                    os.replace(src, dst)
                except Exception as exc:
                    return self._json(False, error="移入回收站失败: %s" % exc)
                return self._json(True, message="已移入回收站: %s" % os.path.basename(dst))
            if self.path == "/api/uninstall":
                d = json.loads(body.decode("utf-8", "replace"))
                r = http_json(APPSTORE + "/app/uninstall", {"code": str(d.get("code", ""))})
                return self._json(r.get("code") == 200, message=r.get("message") or "")
            self._json(False, error="unknown endpoint")
        except Exception as e:
            try:
                self._json(False, error=str(e))
            except Exception:
                pass


if __name__ == "__main__":
    AUTH = load_auth()
    try:
        print("icon heal:", heal_icons())
    except Exception as _e:
        print("icon heal failed:", _e)
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print("TPK installer on 0.0.0.0:%d" % PORT)
    srv.serve_forever()
