#!/usr/bin/env python3

import os
import shutil
import sys

# ── Colors ───────────────────────────────────────────────────────────────────
# Warna ANSI dimatikan otomatis kalau output bukan terminal (pipe/file) atau NO_COLOR di-set.

_ON = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None

RESET = "\033[0m" if _ON else ""

OCEAN_BLUE = "\033[38;5;45m" if _ON else ""
OCEAN_BOLD = "\033[1;38;5;45m" if _ON else ""
PURPLE_BOLD = "\033[1;38;5;165m" if _ON else ""
GRAY = "\033[38;5;245m" if _ON else ""
GRAY_BORDER = "\033[38;5;238m" if _ON else ""
WHITE = "\033[97m" if _ON else ""
GREEN = "\033[92m" if _ON else ""
RED = "\033[91m" if _ON else ""


def color(text: str, style: str) -> str:
    return f"{style}{text}{RESET}"


# ── Banner ───────────────────────────────────────────────────────────────────

def banner(
    identity: str = "[]",
    brand: str = "H I K A R I",
    product: str = " /.CLASH",
    mode: str = "CONVERTER",
    description: str = (
        "Clash (Mihomo) converter + config generator "
        "untuk "
    ),
    info: str = None,
) -> None:
    """info: None = banner saja; "full" / "compact" = tambah info pengguna (sysinfo.py) di bawah banner.
    Pengaturan pengguna (HIKARI_INFO / Misc > Info Banner) jadi batas atas, dan info mati di non-terminal."""
    width = shutil.get_terminal_size((80, 24)).columns
    separator = "─" * min(max(width - 2, 24), 76)

    print()
    print(
        color(f"{identity} ", OCEAN_BLUE)
        + color(brand, PURPLE_BOLD)
        + color(f" {product}", OCEAN_BLUE)
        + color(" // ", GRAY)
        + color(mode, OCEAN_BOLD)
    )
    print(
        color(description, GRAY)
        + color("Box / Nikki / OpenClash", OCEAN_BLUE)
    )
    print(color(separator, GRAY_BORDER))

    if info:
        try:
            import sysinfo
            rows = sysinfo.lines(info, width, _ON)
        except Exception:                # info tidak boleh merusak tampilan menu
            rows = []
        if rows:
            print("\n".join(rows))
            print(color(separator, GRAY_BORDER))


if __name__ == "__main__":
    banner(info="full")