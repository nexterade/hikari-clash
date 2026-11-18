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
) -> None:
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


if __name__ == "__main__":
    banner()