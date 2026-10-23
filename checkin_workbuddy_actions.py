# -*- coding: utf-8 -*-
"""WorkBuddy（腾讯 Copilot 桌面端）签到 —— GitHub Actions 版

模仿 checkin_trae_actions.py：不读本机登录态，凭证全部来自环境变量
（GitHub Secrets），由 Actions 定时执行签到领取积分。

与 Trae 的区别：WorkBuddy 的 accessToken 有效期有限，过期后需用
refreshToken 换新。为避免 refreshToken 链条中断，脚本会把刷新后的
凭证用 WB_STATE_KEY 加密成 wb_state.json 提交回仓库，下次运行时
优先使用状态文件中更新的凭证。

环境变量（二选一）：
  1) 多账号（推荐）：
     WORKBUDDY_ACCOUNTS = [{"name":"wb1","token":"...","refresh_token":"...",
                            "uid":"...","domain":"...","enterprise_id":"...","tenant_id":"..."}, ...]
     （把 --export 生成的 JSON 原样粘贴到 Secret 即可）
  2) 单账号：
     WORKBUDDY_TOKEN          必填，accessToken
     WORKBUDDY_REFRESH_TOKEN  选填，用于自动续期
     WORKBUDDY_UID            选填，账号 uid（请求头 X-User-Id）
     WORKBUDDY_DOMAIN         选填，请求头 X-Domain
     WORKBUDDY_ENTERPRISE_ID  选填，请求头 X-Enterprise-Id
     WORKBUDDY_TENANT_ID      选填，请求头 X-Tenant-Id
     WORKBUDDY_NAME           选填，日志里显示的名称

状态持久化（可选但强烈建议，不设置则 token 过期后需重跑 --export）：
  WB_STATE_KEY   任意足够长的随机字符串；设置后启用加密状态回写
  WB_STATE_FILE  状态文件名，默认 wb_state.json（加密后需提交到仓库）

用法：
  python checkin_workbuddy_actions.py            # 正式签到（查状态 -> 未签则领取）
  python checkin_workbuddy_actions.py --dry-run  # 只查询签到状态，绝不领取（本地测试用）
  python checkin_workbuddy_actions.py --export   # 本机读取 WorkBuddy 登录态，生成 Secrets JSON
                                                 # （优先 Windows DPAPI 解密 CodeBuddy CN 的 state.vscdb；
                                                 #   找不到则回退解密 CodeBuddyExtension 的 *.info 会话文件，
                                                 #   需 pycryptodome，且本机已登录 WorkBuddy/CodeBuddy CN）

安全说明：
  - token 只进 Secret / 内存 / 加密状态文件，不打印；Actions 日志额外 ::add-mask::
  - workbuddy_secrets.json 含明文 token，已在 .gitignore 排除，切勿提交
  - wb_state.json 是 AES-GCM 密文，需提交回仓库以延续登录态
  - 登录态彻底失效后（刷新接口 401/403）需重新打开 WorkBuddy 登录，并重跑 --export 更新 Secret
"""
import argparse
import base64
import ctypes
import hashlib
import json
import os
import re
import struct
import sys
import time
from pathlib import Path

import requests

# ---- 签到 API（参考 traework-checkin-assistant） ----
WB_API_BASE = "https://copilot.tencent.com"
WB_CHECKIN_STATUS_URL = f"{WB_API_BASE}/v2/billing/meter/checkin-activity-status"
WB_CHECKIN_CLAIM_URL = f"{WB_API_BASE}/v2/billing/meter/daily-checkin"
WB_REFRESH_TOKEN_URL = f"{WB_API_BASE}/v2/auth/token/refresh"

WB_UA_FALLBACK = "WorkBuddy/5.5.6"

# ---- 本机登录态位置（--export 用）----
# 新版客户端把 CodeBuddyExtension 下的明文会话文件字段级加密了，
# 改走 CodeBuddy CN（VSCode 壳）的 state.vscdb：Chromium DPAPI + v10 AES-GCM
WB_LOCAL_STATE_REL = Path("CodeBuddy CN") / "Local State"
WB_VSCDB_REL = Path("CodeBuddy CN") / "User" / "globalStorage" / "state.vscdb"
WB_SECRET_KEY = ('secret://{"extensionId":"tencent-cloud.coding-copilot",'
                 '"key":"planning-genie.new.accessTokencn"}')

# 回退来源：WorkBuddy 桌面版把登录态放在 CodeBuddyExtension/Data/Public/auth/*.info，
# 不在 CodeBuddy CN（VSCode 壳）数据目录里；敏感字段为 $wbEncrypted 信封加密
# （AES-256-GCM），密钥由构建期内嵌 atRestSecretKey 派生（同版本通用，与
# checkin_Workbuddy.py 一致）。客户端升级后密钥可能变化，解密失败会明确报错。
WB_EXT_AUTH_REL = Path("CodeBuddyExtension") / "Data" / "Public" / "auth"
WB_AT_REST_SECRET = "Sik9U5aXhCdwTVEwsEySDOmDoB9r9ntFxHF1fst9LQI="

DEFAULT_EXPORT_FILE = Path(__file__).parent / "workbuddy_secrets.json"
DEFAULT_STATE_FILE = Path(__file__).parent / "wb_state.json"

SKEW_SECONDS = 300  # 提前 5 分钟视为过期


# ---- HTTP ----
def api_post(url: str, headers: dict, payload: dict | None = None):
    """POST JSON，返回 (status_code, dict)；响应非 JSON 时 dict 为 {}"""
    r = requests.post(url, headers=headers, json=payload or {}, timeout=30)
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, {}


def detect_wb_version() -> str:
    """从已安装的 WorkBuddy.exe 读版本号，读不到回退默认（仅本地用）"""
    bases = [os.environ.get("LOCALAPPDATA"), os.environ.get("ProgramFiles"),
             os.environ.get("ProgramFiles(x86)")]
    for base in bases:
        if not base:
            continue
        exe = Path(base) / "Programs" / "WorkBuddy" / "WorkBuddy.exe"
        if not exe.exists():
            continue
        try:
            size = ctypes.windll.version.GetFileVersionInfoSizeW(str(exe), None)
            if not size:
                continue
            buf = ctypes.create_string_buffer(size)
            if not ctypes.windll.version.GetFileVersionInfoW(str(exe), 0, size, buf):
                continue
            trans = ctypes.c_void_p()
            ulen = ctypes.c_uint()
            if ctypes.windll.version.VerQueryValueW(
                    buf, "\\VarFileInfo\\Translation", ctypes.byref(trans),
                    ctypes.byref(ulen)) and ulen.value:
                arr = ctypes.cast(trans, ctypes.POINTER(ctypes.c_ushort * 2)).contents
                sub = f"\\StringFileInfo\\{arr[0]:04x}{arr[1]:04x}\\ProductVersion"
                val = ctypes.c_wchar_p()
                vlen = ctypes.c_uint()
                if ctypes.windll.version.VerQueryValueW(
                        buf, sub, ctypes.byref(val), ctypes.byref(vlen)) and val.value:
                    parts = val.value.strip().split(".")
                    return ".".join(parts[:3]) if len(parts) >= 3 else val.value.strip()
        except Exception:
            continue
    return WB_UA_FALLBACK.split("/")[-1]


def build_headers(sec: dict, ua: str | None = None) -> dict:
    h = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": f"Bearer {sec.get('token', '')}",
        "X-User-Id": sec.get("uid", ""),
        "User-Agent": ua or f"WorkBuddy/{WB_UA_FALLBACK.split('/')[-1]}",
    }
    if sec.get("domain"):
        h["X-Domain"] = sec["domain"]
    if sec.get("enterprise_id"):
        h["X-Enterprise-Id"] = str(sec["enterprise_id"])
    if sec.get("tenant_id"):
        h["X-Tenant-Id"] = str(sec["tenant_id"])
    return h


# ---- 凭证过期与续期 ----
def _jwt_exp(token: str):
    parts = token.split(".")
    if len(parts) < 2:
        return None
    try:
        payload = parts[1] + "=" * (-len(parts[1]) % 4)
        return json.loads(base64.b64decode(payload)).get("exp")
    except Exception:
        return None


def is_expired(sec: dict, skew: int = SKEW_SECONDS) -> bool:
    exp = sec.get("expires_at")
    try:
        if exp:
            exp = int(exp)
            if exp > 10_000_000_000:  # 毫秒时间戳
                return time.time() > exp / 1000 - skew
            return time.time() > exp - skew
    except (TypeError, ValueError):
        pass
    exp = _jwt_exp(sec.get("token", ""))
    if exp:
        return time.time() > exp - skew
    return False


def refresh_token(sec: dict, ua: str | None = None) -> None:
    """用 refreshToken 换新 accessToken，原地更新 sec 各字段"""
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "X-Refresh-Token": sec.get("refresh_token", ""),
        "X-Auth-Refresh-Source": "plugin",
        "User-Agent": ua or f"WorkBuddy/{WB_UA_FALLBACK.split('/')[-1]}",
    }
    if sec.get("token"):
        headers["Authorization"] = f"Bearer {sec['token']}"
    if sec.get("domain"):
        headers["X-Domain"] = sec["domain"]
    status, resp = api_post(WB_REFRESH_TOKEN_URL, headers)
    if status in (401, 403):
        raise RuntimeError("登录态已失效（刷新接口 401/403），"
                           "请重新打开 WorkBuddy 登录后重跑 --export 更新 Secret")
    if status != 200:
        raise RuntimeError(f"刷新凭证失败 (HTTP {status})")
    new_auth = resp.get("data") if isinstance(resp.get("data"), dict) else None
    if not new_auth or not new_auth.get("accessToken"):
        raise RuntimeError("刷新凭证响应异常")
    now_ms = int(time.time() * 1000)
    expires_in = int(new_auth.get("expiresIn", 259200) or 259200)
    refresh_in = int(new_auth.get("refreshExpiresIn", 604799) or 604799)
    sec["token"] = new_auth["accessToken"]
    if new_auth.get("refreshToken"):
        sec["refresh_token"] = new_auth["refreshToken"]
    sec["expires_at"] = new_auth.get("expiresAt") or (now_ms + expires_in * 1000)
    sec["refresh_expires_at"] = (new_auth.get("refreshExpiresAt")
                                 or (now_ms + refresh_in * 1000))
    if new_auth.get("domain"):
        sec["domain"] = new_auth["domain"]


# ---- 已签到判定（兼容多种返回形态） ----
def is_already_checked_in(code, msg: str) -> bool:
    if code in (10001, 1001):
        return True
    if msg and ("已签到" in msg or "已领取" in msg or "明天再来" in msg):
        return True
    return False


def _recheck(headers: dict, ua: str) -> dict | None:
    """领取响应异常时回查状态，已签则返回成功结果片段"""
    try:
        rc, rr = api_post(WB_CHECKIN_STATUS_URL, build_headers(
            {"token": headers.get("Authorization", "").replace("Bearer ", ""),
             "uid": headers.get("X-User-Id", ""),
             "domain": headers.get("X-Domain", ""),
             "enterprise_id": headers.get("X-Enterprise-Id", ""),
             "tenant_id": headers.get("X-Tenant-Id", "")}, ua))
    except Exception:
        return None
    if rc in (401, 403):
        return None
    data = rr.get("data") if isinstance(rr, dict) else None
    if rc == 200 and isinstance(data, dict) and data.get("today_checked_in"):
        return {"ok": True, "checked_in": True, "credits": data.get("total_credits")}
    return None


# ---- 单账号签到 ----
def ensure_fresh(sec: dict, name: str, ua: str) -> bool:
    """过期则刷新（原地更新并打 _refreshed 标记），失败返回 False"""
    if not is_expired(sec):
        return True
    print(f"[{name}] token 即将过期，正在用 refreshToken 自动续期...")
    try:
        refresh_token(sec, ua)
        sec["_refreshed"] = True
        return True
    except RuntimeError as e:
        print(f"[{name}] {e}")
        return False


def run_account(acc: dict, dry_run: bool, ua: str) -> bool:
    name = acc["name"]
    if not acc.get("token"):
        print(f"[{name}] 凭证中缺少 token")
        return False
    if not ensure_fresh(acc, name, ua):
        return False

    headers = build_headers(acc, ua)
    try:
        st_code, st_resp = api_post(WB_CHECKIN_STATUS_URL, headers)
    except Exception as e:
        print(f"[{name}] 查询签到状态失败：{e}")
        return False
    if st_code in (401, 403):
        print(f"[{name}] 登录态已失效(HTTP {st_code})，"
              f"请重新打开 WorkBuddy 登录后重跑 --export 更新 Secret")
        return False

    st_data = st_resp.get("data") if isinstance(st_resp, dict) else None
    st_env = st_resp.get("code") if isinstance(st_resp, dict) else None
    st_msg = ((st_resp.get("msg") or st_resp.get("message") or "")
              if isinstance(st_resp, dict) else "")
    if st_code != 200 or not isinstance(st_data, dict):
        if is_already_checked_in(st_env, st_msg):
            print(f"[{name}] 今日已签到")
            return True
        print(f"[{name}] 查询签到状态失败 (HTTP {st_code} {st_env} {st_msg})")
        return False

    active = st_data.get("active", True)
    checked_in = bool(st_data.get("today_checked_in"))
    credits = st_data.get("total_credits")
    streak = st_data.get("streak_days")

    if dry_run:
        msg = "签到活动暂未开启" if not active else (
            "今日已签到" + (f"，连续 {streak} 天" if streak else "")
            if checked_in else "今日尚未签到")
        print(f"[{name}] (dry-run) {msg}，当前积分：{credits if credits is not None else '?'}")
        return True

    if not active:
        print(f"[{name}] 签到活动暂未开启或已结束")
        return False
    if checked_in:
        print(f"[{name}] 今日已签到" + (f"，连续 {streak} 天" if streak else "")
              + f"，当前积分：{credits if credits is not None else '?'}")
        return True

    try:
        c_code, c_resp = api_post(WB_CHECKIN_CLAIM_URL, headers)
    except Exception as e:
        recheck = _recheck(headers, ua)
        if recheck:
            print(f"[{name}] 签到异常但回查确认已到账")
            return True
        print(f"[{name}] 签到请求失败：{e}")
        return False
    if c_code in (401, 403):
        print(f"[{name}] 登录态已失效(HTTP {c_code})，请重新登录 WorkBuddy")
        return False

    c_data = c_resp.get("data") if isinstance(c_resp, dict) else None
    c_env = c_resp.get("code") if isinstance(c_resp, dict) else None
    c_msg = ((c_resp.get("msg") or c_resp.get("message") or "")
             if isinstance(c_resp, dict) else "")
    if is_already_checked_in(c_env, c_msg):
        print(f"[{name}] 今日已签到")
        return True
    if c_code != 200 or not isinstance(c_data, dict):
        recheck = _recheck(headers, ua)
        if recheck:
            print(f"[{name}] 签到响应异常(HTTP {c_code})但回查确认已到账")
            return True
        print(f"[{name}] 签到失败（HTTP {c_code} {c_env} {c_msg}）")
        return False

    gained = c_data.get("credit")
    streak = c_data.get("streak_days")
    total = c_data.get("total_credits", credits)
    confirmed = bool(c_data.get("today_checked_in") or c_data.get("checked_in")
                     or c_data.get("success") is True or total is not None
                     or gained is not None)
    if not confirmed:
        print(f"[{name}] ⚠ 签到流程已执行，但未抓到积分/成功信号，"
              f"疑似客户端改版，请人工打开客户端确认；"
              f"领取响应字段：{sorted(c_data.keys())}")
        return False
    msg = "签到成功"
    if gained is not None:
        msg += f"，获得 {gained} 积分"
        if streak:
            msg += f"，连续签到 {streak} 天"
    print(f"[{name}] {msg}，当前积分：{total if total is not None else '?'}")
    return True


# ---- 凭证来源：环境变量 + 加密状态文件 ----
ACC_FIELDS = ("token", "refresh_token", "uid", "domain",
              "enterprise_id", "tenant_id", "expires_at", "refresh_expires_at")


def accounts_from_env() -> list:
    raw = os.environ.get("WORKBUDDY_ACCOUNTS", "").strip()
    if raw:
        data = json.loads(raw)
        items = data if isinstance(data, list) else [data]
        accs = []
        for it in items:
            if not it.get("token"):
                raise ValueError("WORKBUDDY_ACCOUNTS 中存在缺少 token 的条目")
            acc = {"name": it.get("name") or "workbuddy"}
            for f in ACC_FIELDS:
                if it.get(f):
                    acc[f] = it[f]
            accs.append(acc)
        return accs
    token = os.environ.get("WORKBUDDY_TOKEN", "").strip()
    if token:
        acc = {"name": os.environ.get("WORKBUDDY_NAME", "workbuddy"), "token": token}
        for env_name, field in (("WORKBUDDY_REFRESH_TOKEN", "refresh_token"),
                                ("WORKBUDDY_UID", "uid"),
                                ("WORKBUDDY_DOMAIN", "domain"),
                                ("WORKBUDDY_ENTERPRISE_ID", "enterprise_id"),
                                ("WORKBUDDY_TENANT_ID", "tenant_id")):
            v = os.environ.get(env_name, "").strip()
            if v:
                acc[field] = v
        return acc
    return []


def _state_cipher():
    from Crypto.Cipher import AES
    key = hashlib.sha256(os.environ["WB_STATE_KEY"].encode("utf-8")).digest()
    return key, AES


def load_state(path: Path) -> dict:
    """解密状态文件，返回 {账号键: {字段: 值}}；失败返回 {}"""
    if not (os.environ.get("WB_STATE_KEY") and path.exists()):
        return {}
    try:
        from Crypto.Cipher import AES
        key, AES = _state_cipher()
        blob = base64.b64decode(path.read_bytes())
        nonce, ct, tag = blob[:12], blob[12:-16], blob[-16:]
        plain = AES.new(key, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ct, tag)
        data = json.loads(plain.decode("utf-8"))
        return data.get("accounts", {}) if isinstance(data, dict) else {}
    except Exception as e:
        print(f"WARN: 状态文件解密失败，忽略（{e}）")
        return {}


def merge_state(accs: list, state: dict) -> None:
    """状态文件中更新的凭证覆盖 Secret 中的旧凭证（按 expires_at 取新）"""
    for acc in accs:
        key = acc.get("uid") or acc["name"]
        cached = state.get(key)
        if not cached:
            continue
        try:
            new_exp = int(acc.get("expires_at") or 0)
            old_exp = int(cached.get("expires_at") or 0)
        except (TypeError, ValueError):
            continue
        if old_exp > new_exp and cached.get("token"):
            for f in ACC_FIELDS:
                if cached.get(f):
                    acc[f] = cached[f]


def save_state(accs: list, path: Path) -> bool:
    """有账号续期过则加密写入状态文件，供 workflow 提交回仓库"""
    if not os.environ.get("WB_STATE_KEY"):
        return False
    changed = [a for a in accs if a.get("_refreshed")]
    if not changed:
        return False
    from Crypto.Cipher import AES
    key, AES = _state_cipher()
    accounts = {}
    for a in accs:
        entry = {f: a[f] for f in ACC_FIELDS if a.get(f)}
        accounts[a.get("uid") or a["name"]] = entry
    nonce = os.urandom(12)
    plain = json.dumps({"accounts": accounts, "saved_at": int(time.time())},
                       ensure_ascii=False).encode("utf-8")
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(plain)
    path.write_bytes(base64.b64encode(nonce + ct + tag))
    print(f"已更新加密状态文件 {path.name}（{len(changed)} 个账号续期），"
          f"workflow 会将其提交回仓库")
    return True


def mask_tokens(accs: list) -> None:
    """Actions 日志中动态掩码 token（Secrets 本身也会被 GitHub 自动掩码，双保险）"""
    if os.environ.get("GITHUB_ACTIONS") == "true":
        for a in accs:
            for f in ("token", "refresh_token"):
                if a.get(f):
                    print(f"::add-mask::{a[f]}")


# ---- --export：本机读取登录态，生成 Secrets JSON ----
def _wb_field_aad(key_id: str, suite: int) -> bytes:
    """复刻 WorkBuddy buildAuthenticatedContextAad（sym-v1，field 级）的字节布局"""
    return b"".join([
        b"WB-AAD\x00", b"\x01",
        struct.pack(">I", len(b"WBEV1")) + b"WBEV1",
        struct.pack(">I", 6) + b"sym-v1",
        struct.pack(">I", suite),
        struct.pack(">I", len(key_id)) + key_id.encode(),
        bytes([2]),  # _FRAMING_NUM["field"]
        b"\x00",     # sequence 未定义
        b"\x00",     # final 未定义
    ])


def _open_wb_field(value):
    """解密 $wbEncrypted 字段封装；明文值原样返回。失败抛异常。"""
    if not isinstance(value, dict) or value.get("$wbEncrypted") != 1:
        return value
    if value.get("scheme") not in (None, "sym-v1"):
        raise ValueError(f"不支持的加密方案 {value.get('scheme')}，请重新登录 WorkBuddy")
    from Crypto.Cipher import AES
    key = hashlib.sha256(WB_AT_REST_SECRET.encode("utf-8")).digest()
    key_id = hashlib.sha256(key).hexdigest()[:16]
    env = json.loads(base64.b64decode(value["envelope"]))
    if env.get("keyId") != key_id:
        raise ValueError(f"密钥不匹配（envelope keyId={env.get('keyId')}），"
                         "WorkBuddy 版本可能已更新")
    cipher = AES.new(key, AES.MODE_GCM, nonce=base64.b64decode(env["nonce"]))
    cipher.update(_wb_field_aad(env["keyId"], env["suite"]))
    plain = cipher.decrypt_and_verify(
        base64.b64decode(env["ciphertext"]), base64.b64decode(env["authTag"]))
    return plain.decode("utf-8")


def _load_session_ext() -> dict:
    """回退来源：从 CodeBuddyExtension 的 *.info 会话文件解密 WorkBuddy 登录态。
    返回第一个可用的会话（单账号导出；多账号见 checkin_Workbuddy.py）。"""
    auth_dir = Path(os.environ.get("LOCALAPPDATA", "")) / WB_EXT_AUTH_REL
    if not auth_dir.is_dir():
        raise FileNotFoundError(f"未找到 {auth_dir}")
    files = sorted(auth_dir.glob("*.info"))
    if not files:
        raise FileNotFoundError(f"{auth_dir} 下没有 .info 会话文件")
    last_err: Exception | None = None
    for path in files:
        try:
            sess = json.loads(path.read_text(encoding="utf-8"))
            for section in ("auth", "account"):
                obj = sess.get(section)
                if not isinstance(obj, dict):
                    continue
                for k, v in list(obj.items()):
                    if isinstance(v, dict) and v.get("$wbEncrypted") == 1:
                        obj[k] = _open_wb_field(v)
            if not sess.get("auth", {}).get("accessToken"):
                raise ValueError("会话文件中无 accessToken")
            return sess
        except Exception as e:  # 换下一个文件试
            last_err = e
    raise ValueError(f"解析会话文件失败：{last_err}")


def _load_session() -> dict:
    """读取本机 WorkBuddy 登录态：优先 CodeBuddy CN 的 state.vscdb，
    找不到/读不了时回退 CodeBuddyExtension 的 *.info 会话文件"""
    try:
        return _load_session_vscdb()
    except Exception as e:
        print(f"（state.vscdb 读取失败：{e}）")
        print("（回退读取 CodeBuddyExtension 会话文件）")
        return _load_session_ext()


def _dpapi_decrypt(raw: bytes) -> bytes:
    buf = ctypes.create_string_buffer(raw, len(raw))

    class _BLOB(ctypes.Structure):
        _fields_ = [("cbData", ctypes.c_ulong),
                    ("pbData", ctypes.POINTER(ctypes.c_char))]

    blob_in = _BLOB(len(raw), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    blob_out = _BLOB()
    if not ctypes.windll.crypt32.CryptUnprotectData(
            ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out)):
        raise OSError("DPAPI 解密失败")
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(blob_out.pbData)


def _load_session_vscdb() -> dict:
    """从 CodeBuddy CN 的 state.vscdb 解密 WorkBuddy 会话（Windows DPAPI，需 pycryptodome）"""
    import shutil
    import sqlite3
    import tempfile
    from Crypto.Cipher import AES

    if os.name != "nt":
        raise OSError("export 仅支持 Windows（依赖 DPAPI）；"
                      "其他平台请在 Windows 上导出后手动粘贴 token")
    appdata = os.environ.get("APPDATA", "")
    ls_path = Path(appdata) / WB_LOCAL_STATE_REL
    db_path = Path(appdata) / WB_VSCDB_REL
    if not ls_path.exists():
        raise FileNotFoundError(f"未找到 {ls_path}，请确认本机安装并登录过 CodeBuddy CN / WorkBuddy")
    if not db_path.exists():
        raise FileNotFoundError(f"未找到 {db_path}")
    ls = json.loads(ls_path.read_text(encoding="utf-8"))
    enc = base64.b64decode(ls["os_crypt"]["encrypted_key"])
    if enc[:5] != b"DPAPI":
        raise ValueError("Local State 主密钥格式异常")
    key = _dpapi_decrypt(enc[5:])

    db_copy = Path(tempfile.gettempdir()) / "wb_state_export.vscdb"
    try:
        shutil.copy2(db_path, db_copy)
    except Exception:
        db_copy = db_path  # 拷贝失败则直接只读打开
    con = sqlite3.connect(f"file:{db_copy}?mode=ro", uri=True)
    try:
        row = con.execute("SELECT value FROM ItemTable WHERE key = ?",
                          (WB_SECRET_KEY,)).fetchone()
    finally:
        con.close()
    if not row:
        raise KeyError("state.vscdb 中未找到 WorkBuddy 登录凭证")
    v = row[0]
    if isinstance(v, str):
        s = v.strip()
        try:
            o = json.loads(s)
        except (json.JSONDecodeError, ValueError):
            o = None
        if isinstance(o, dict) and o.get("type") == "Buffer":
            blob = bytes(o.get("data", []))
        else:
            blob = s.encode("latin1", errors="ignore")
    else:
        blob = bytes(v)
    if blob[:3] not in (b"v10", b"v20"):
        raise ValueError("不是 v10/v20 密文")
    plain = AES.new(key, AES.MODE_GCM, nonce=blob[3:15]).decrypt_and_verify(
        blob[15:-16], blob[-16:])
    data = json.loads(plain.decode("utf-8"))
    if not data.get("auth", {}).get("accessToken"):
        raise ValueError("解密得到的会话不完整")
    return data


def _secret_obj(sess: dict) -> dict:
    auth = sess.get("auth", {})
    acc = sess.get("account", {})
    out = {
        "token": auth.get("accessToken", ""),
        "refresh_token": auth.get("refreshToken", ""),
        "expires_at": auth.get("expiresAt", 0),
        "refresh_expires_at": auth.get("refreshExpiresAt", 0),
        "uid": acc.get("uid", ""),
        "domain": auth.get("domain", ""),
        "enterprise_id": acc.get("enterpriseId", "") or acc.get("tenantId", ""),
        "tenant_id": acc.get("tenantId", "") or acc.get("enterpriseId", ""),
    }
    return {k: v for k, v in out.items() if v}


def export_secrets(out_path: Path) -> int:
    try:
        sess = _load_session()
    except Exception as e:
        print(f"读取 WorkBuddy 登录态失败：{e}")
        print("请先安装并登录 WorkBuddy / CodeBuddy CN 客户端后重试")
        return 1

    sec = _secret_obj(sess)
    if not sec.get("token"):
        print("登录态中无 token，请先在 WorkBuddy 客户端登录")
        return 1
    acc_name = (sess.get("account", {}).get("nickname")
                or sess.get("account", {}).get("phoneNumber") or "WorkBuddy")
    payload = [{"name": acc_name, **sec}]
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2),
                        encoding="utf-8")

    exp = sec.get("expires_at")
    try:
        exp_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(int(exp) / 1000
                                if int(exp) > 10_000_000_000 else int(exp)))
    except (TypeError, ValueError):
        exp_str = "?"
    print(f"已生成 {out_path}")
    print(f"  账号          : {acc_name}")
    print(f"  token         : ******{sec['token'][-6:]}")
    print(f"  refresh_token : {'(无)' if not sec.get('refresh_token') else '******' + sec['refresh_token'][-6:]}")
    print(f"  uid           : {sec.get('uid', '(空)')}")
    print(f"  domain        : {sec.get('domain', '(空)')}")
    print(f"  token 过期时间: {exp_str}")
    print()
    print("下一步：GitHub 仓库 -> Settings -> Secrets and variables -> Actions")
    print("  -> New repository secret：Name 填 WORKBUDDY_ACCOUNTS，Secret 粘贴该文件全部内容")
    print("  -> 另建 Secret：Name 填 WB_STATE_KEY，值为任意足够长的随机字符串（启用自动续期）")
    print(f"注意：{out_path.name} 含明文 token，切勿提交到仓库（已在 .gitignore 中排除）")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="WorkBuddy 签到（GitHub Actions 版）")
    ap.add_argument("--dry-run", action="store_true", help="只查询签到状态，不领取")
    ap.add_argument("--export", action="store_true", help="本机读取登录态，生成 Secrets JSON")
    ap.add_argument("--out", default=str(DEFAULT_EXPORT_FILE), help="export 输出路径")
    ap.add_argument("--state", default=str(
        os.environ.get("WB_STATE_FILE", DEFAULT_STATE_FILE)), help="加密状态文件路径")
    args = ap.parse_args()

    if args.export:
        return export_secrets(Path(args.out))

    try:
        accs = accounts_from_env()
    except (ValueError, json.JSONDecodeError) as e:
        print(f"ERROR: WORKBUDDY_ACCOUNTS 解析失败：{e}")
        return 1
    if not accs:
        print("ERROR: 未配置凭证。请设置 WORKBUDDY_ACCOUNTS（推荐）或 WORKBUDDY_TOKEN 环境变量；"
              "本机可先运行 python checkin_workbuddy_actions.py --export 生成")
        return 1

    merge_state(accs, load_state(Path(args.state)))
    ua = detect_wb_version()
    mask_tokens(accs)
    results = [run_account(a, args.dry_run, ua) for a in accs]
    save_state(accs, Path(args.state))
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())