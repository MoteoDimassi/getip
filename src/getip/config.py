"""Настройки в ~/.config/getip/config.json."""
import json
import os

CONFIG_PATH = os.path.expanduser("~/.config/getip/config.json")
DEFAULTS = {"gw": "0.0.0.0", "persistent": False, "exact": False,
            "out_dir": "", "deep_seconds": 60, "last_domain": "", "fit_window": True}


def load_config():
    cfg = dict(DEFAULTS)
    try:
        with open(CONFIG_PATH, encoding="utf-8") as f:
            cfg.update(json.load(f))
    except (OSError, ValueError):
        pass
    return cfg


def save_config(cfg):
    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)


def out_dir(cfg):
    return os.path.abspath(os.path.expanduser(cfg["out_dir"] or os.getcwd()))
