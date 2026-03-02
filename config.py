"""
配置加载器 - 从 config.json 读取路径配置
首次运行时自动生成 config.json 模板
"""
import json, os, sys, glob

CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")

_DEFAULT = {
    "db_dir": "~/Library/Containers/com.tencent.xinWeChat/Data/Library/Application Support/com.tencent.xinWeChat/2.0b4.0.9/<user_hash>",
    "keys_file": "all_keys.json",
    "decrypted_dir": "decrypted",
    "wechat_process": "WeChat",
}

_WECHAT_BASE = os.path.expanduser(
    "~/Library/Containers/com.tencent.xinWeChat/Data/Library/"
    "Application Support/com.tencent.xinWeChat/2.0b4.0.9/"
)


def _detect_db_dir():
    """自动查找微信数据库目录（遍历 <user_hash> 子目录，选 .db 文件最多的）"""
    if not os.path.isdir(_WECHAT_BASE):
        return None
    candidates = [
        d for d in os.listdir(_WECHAT_BASE)
        if os.path.isdir(os.path.join(_WECHAT_BASE, d)) and len(d) > 10
    ]
    if not candidates:
        return None
    best = max(
        candidates,
        key=lambda h: len(glob.glob(os.path.join(_WECHAT_BASE, h, "**/*.db"), recursive=True))
    )
    return os.path.join(_WECHAT_BASE, best)


def load_config():
    if not os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "w") as f:
            json.dump(_DEFAULT, f, indent=4)
        print(f"[!] 已生成配置文件: {CONFIG_FILE}", file=sys.stderr)
        print("    请修改 config.json 中的路径后重新运行", file=sys.stderr)
        sys.exit(1)

    with open(CONFIG_FILE) as f:
        cfg = json.load(f)

    base = os.path.dirname(os.path.abspath(__file__))
    for key in ("keys_file", "decrypted_dir"):
        if key in cfg and not os.path.isabs(cfg[key]):
            cfg[key] = os.path.join(base, cfg[key])

    if "db_dir" in cfg:
        cfg["db_dir"] = os.path.expanduser(cfg["db_dir"])

    # 如果 db_dir 包含占位符或目录不存在，自动检测
    db_dir = cfg.get("db_dir", "")
    if "<user_hash>" in db_dir or not os.path.isdir(db_dir):
        detected = _detect_db_dir()
        if detected:
            print(f"[auto] db_dir 自动检测: {detected}", file=sys.stderr)
            cfg["db_dir"] = detected
        elif "<user_hash>" in db_dir:
            print("[ERROR] db_dir 未配置且无法自动检测，请手动设置 config.json", file=sys.stderr)
            sys.exit(1)

    return cfg
