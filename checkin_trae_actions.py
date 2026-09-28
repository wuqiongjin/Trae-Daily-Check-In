# -*- coding: utf-8 -*-
"""Trae CN / TRAE SOLO CN 签到 —— GitHub Actions 版

与 checkin_trae.py 的区别：不读本机登录态文件，凭证全部来自环境变量
（GitHub Secrets），适合放到 GitHub Actions 定时执行。

环境变量（二选一）：
  1) 多账号（推荐）：
     TRAE_ACCOUNTS = [{"name":"trae1","token":"...","device_id":"...","region":"CN"}, ...]
     （把 --export 生成的 JSON 原样粘贴到 Secret 即可）
  2) 单账号：
     TRAE_TOKEN       必填，Cloud-IDE-JWT token
     TRAE_DEVICE_ID   选填，设备 ID
     TRAE_REGION      选填，用户区域
     TRAE_NAME        选填，日志里显示的名称

用法：
  python checkin_trae_actions.py            # 正式签到（查状态 -> 未签则领取）
  python checkin_trae_actions.py --dry-run  # 只查询签到状态，绝不领取（本地测试用）
  python checkin_trae_actions.py --export   # 本机解密 Trae CN 登录态，生成 Secrets JSON
                                            # （需 pycryptodome，且本机已登录 Trae CN）

安全说明：
  - token 只进 Secret / 内存，不打印；Actions 日志里额外做 ::add-mask::
  - 登录态过期后（HTTP 401/403）需重新打开 Trae CN 登录，并重跑 --export 更新 Secret
"""
import argparse
import base64
import hashlib
import json
import os
import re
import sys
from pathlib import Path

import requests

# ---- 与 checkin_trae.py 一致的常量 ----
AUTH_KEY = "iCubeAuthInfo://icube.cloudide"
API_BASE = "https://api.trae.cn/trae/api/v2/ug/checkin_credits"
REQ_SOURCE = 1  # 1=Trae CN IDE；2=SOLO/企业版

HDR_LEN = 6
KEY_LEN = 32
HMAC_LEN = 64
URE = bytes([82,9,106,213,48,54,165,56,191,64,163,158,129,243,215,251,124,227,57,130,155,47,255,135,52,142,67,68,196,222,233,203,84,123,148,50,166,194,35,61,238,76,149,11,66,250,195,78,8,46,161,102,40,217,36,178,118,91,162,73,109,139,209,37])
DRE = bytes([31,221,168,51,136,7,199,49,177,18,16,89,39,128,236,95,96,81,127,169,25,181,74,13,45,229,122,159,147,201,156,239,160,224,59,77,174,42,245,176,200,235,187,60,131,83,153,97,23,43,4,126,186,119,214,38,225,105,20,99,85,33,12,125])

APP_DIR = Path(os.environ.get("APPDATA", "")) / "Trae CN"
DEFAULT_EXPORT_FILE = Path(__file__).parent / "trae_secrets.json"


# ---- 仅 --export 本地解密时才需要 pycryptodome（Actions 上不导入） ----
def decrypt_auth(b64_text: str) -> dict:
    """解密 iCubeAuthInfo 加密串，返回含 token / userRegion 的 dict"""
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad

    t = base64.b64decode(b64_text)
    key = t[HDR_LEN:HDR_LEN + KEY_LEN]
    sha = hashlib.sha512(key).digest()
    xor = bytes(a ^ b for a, b in zip(URE, DRE))
    h = hashlib.sha512(sha + xor).digest()
    aes_key, iv = h[:16], h[16:32]
    ct = t[HDR_LEN + KEY_LEN:]
    plain = unpad(AES.new(aes_key, AES.MODE_CBC, iv).decrypt(ct), AES.block_size)
    return json.loads(plain[HMAC_LEN:].decode("utf-8"))


def load_device_id() -> str:
    """设备 ID：ahanet 配置 → 客户端日志 → 空串兜底"""
    p = APP_DIR / "ahanet" / "tt_net_config.config"
    try:
        m = re.search(r"device_id[^\w]*(\d+)", p.read_text(encoding="utf-8", errors="ignore"))
        if m:
            return m.group(1)
    except OSError:
        pass
    logs_dir = APP_DIR / "logs"
    if logs_dir.is_dir():
        try:
            mains = sorted(logs_dir.glob("*/main.log"),
                           key=lambda p: p.stat().st_mtime, reverse=True)
        except OSError:
            mains = []
        for p in mains[:5]:
            try:
                m = re.search(r"\[ICDRS\].*?did: (\d+)",
                              p.read_text(encoding="utf-8", errors="ignore"))
                if m:
                    return m.group(1)
            except OSError:
                continue
    return ""


# ---- 签到 API（与 checkin_trae.py 一致） ----
def api(url: str, token: str, region: str, device_id: str) -> dict:
    headers = {
        "Authorization": f"Cloud-IDE-JWT {token}",
        "Content-Type": "application/json",
        "x-device-id": device_id,
    }
    if region:
        headers["X-User-Region"] = region
    r = requests.post(url, headers=headers, json={"req_source": REQ_SOURCE}, timeout=30)
    r.raise_for_status()
    return r.json()


def unwrap(resp: dict) -> dict:
    """兼容 {checked_in:...} 与 {code:0, data:{checked_in:...}} 两种返回格式"""
    if ("checked_in" not in resp and isinstance(resp.get("data"), dict)
            and "checked_in" in resp["data"]):
        return resp["data"]
    return resp


# ---- 凭证来源：环境变量 ----
def accounts_from_env() -> list:
    raw = os.environ.get("TRAE_ACCOUNTS", "").strip()
    if raw:
        data = json.loads(raw)
        items = data if isinstance(data, list) else [data]
        accs = []
        for it in items:
            if not it.get("token"):
                raise ValueError("TRAE_ACCOUNTS 中存在缺少 token 的条目")
            accs.append({
                "name": it.get("name") or "trae",
                "token": it["token"],
                "device_id": it.get("device_id") or "",
                "region": it.get("region") or "",
            })
        return accs
    token = os.environ.get("TRAE_TOKEN", "").strip()
    if token:
        return [{
            "name": os.environ.get("TRAE_NAME", "trae"),
            "token": token,
            "device_id": os.environ.get("TRAE_DEVICE_ID", ""),
            "region": os.environ.get("TRAE_REGION", ""),
        }]
    return []


def mask_tokens(accounts: list) -> None:
    """Actions 日志中动态掩码 token（Secrets 本身也会被 GitHub 自动掩码，双保险）"""
    if os.environ.get("GITHUB_ACTIONS") == "true":
        for a in accounts:
            if a.get("token"):
                print(f"::add-mask::{a['token']}")


def run_account(acc: dict, dry_run: bool) -> bool:
    name, token = acc["name"], acc["token"]
    region, device_id = acc["region"], acc["device_id"]
    try:
        status = unwrap(api(f"{API_BASE}/status", token, region, device_id))
    except requests.HTTPError as e:
        code = e.response.status_code if e.response is not None else "?"
        print(f"[{name}] 查询签到状态失败(HTTP {code})，token 可能已过期"
              f" -> 重新登录 Trae CN 后重跑 --export 更新 Secret")
        return False
    except Exception as e:
        print(f"[{name}] 网络错误：{e}")
        return False

    if dry_run:
        print(f"[{name}] (dry-run) 状态：{json.dumps(status, ensure_ascii=False)[:200]}")
        return True

    if status.get("checked_in"):
        print(f"[{name}] 今日已签到，当前积分：{status.get('credits')}")
        return True
    if not status.get("enable"):
        print(f"[{name}] 签到不可用：{json.dumps(status, ensure_ascii=False)[:200]}")
        return False

    try:
        claim = api(f"{API_BASE}/claim", token, region, device_id)
    except Exception as e:
        print(f"[{name}] 领取积分失败：{e}")
        return False

    if claim.get("code") == 0:
        try:
            after = unwrap(api(f"{API_BASE}/status", token, region, device_id))
            print(f"[{name}] 签到成功，当前积分：{after.get('credits', '?')}")
        except Exception:
            print(f"[{name}] 签到成功")
        return True
    print(f"[{name}] 签到失败：{claim.get('message') or json.dumps(claim, ensure_ascii=False)[:200]}")
    return False


# ---- --export：本机解密登录态，生成 Secrets JSON ----
def export_secrets(out_path: Path) -> int:
    sf = APP_DIR / "User" / "globalStorage" / "storage.json"
    if not sf.exists():
        print(f"未找到 {sf}，请先安装并登录 Trae CN 客户端")
        return 1
    try:
        storage = json.loads(sf.read_text(encoding="utf-8"))
        enc = storage.get(AUTH_KEY)
        if not enc:
            print("storage.json 中无登录态（iCubeAuthInfo），请先在 Trae CN 内登录")
            return 1
        auth = decrypt_auth(enc)
    except Exception as e:
        print(f"解密失败：{e}")
        return 1

    token = auth.get("token") or ""
    if not token:
        print("登录态中无 token，请重新登录 Trae CN")
        return 1
    region = (auth.get("userRegion") or {}).get("region") or ""
    device_id = load_device_id()

    payload = [{"name": "Trae CN", "token": token, "device_id": device_id, "region": region}]
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"已生成 {out_path}")
    print(f"  账号      : Trae CN")
    print(f"  token     : ******{token[-6:]}")
    print(f"  device_id : {'(空，可省略)' if not device_id else '******' + device_id[-4:]}")
    print(f"  region    : {region or '(空)'}")
    print()
    print("下一步：GitHub 仓库 -> Settings -> Secrets and variables -> Actions")
    print("  -> New repository secret：Name 填 TRAE_ACCOUNTS，Secret 粘贴该文件全部内容")
    print(f"注意：{out_path.name} 含明文 token，切勿提交到仓库（已在 .gitignore 中排除）")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Trae CN 签到（GitHub Actions 版）")
    ap.add_argument("--dry-run", action="store_true", help="只查询签到状态，不领取")
    ap.add_argument("--export", action="store_true", help="本机解密登录态，生成 Secrets JSON")
    ap.add_argument("--out", default=str(DEFAULT_EXPORT_FILE), help="export 输出路径")
    args = ap.parse_args()

    if args.export:
        return export_secrets(Path(args.out))

    try:
        accounts = accounts_from_env()
    except (ValueError, json.JSONDecodeError) as e:
        print(f"ERROR: TRAE_ACCOUNTS 解析失败：{e}")
        return 1
    if not accounts:
        print("ERROR: 未配置凭证。请设置 TRAE_ACCOUNTS（推荐）或 TRAE_TOKEN 环境变量；"
              "本机可先运行 python checkin_trae_actions.py --export 生成")
        return 1

    mask_tokens(accounts)
    results = [run_account(a, args.dry_run) for a in accounts]
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
