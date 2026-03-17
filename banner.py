import io
import os
import sys

# Ensure stdout can handle Unicode box-drawing chars on Windows
if sys.platform == 'win32' and hasattr(sys.stdout, 'buffer'):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

# ANSI colours — disabled automatically on Windows without ANSI support or when
# output is redirected (e.g. piped to a file).
def _ansi_supported() -> bool:
    if os.environ.get('NO_COLOR'):
        return False
    if not hasattr(sys.stdout, 'isatty') or not sys.stdout.isatty():
        return False
    if sys.platform == 'win32':
        # Windows 10 1511+ supports ANSI in conhost/WT; enable it via kernel call
        try:
            import ctypes
            kernel = ctypes.windll.kernel32
            kernel.SetConsoleMode(kernel.GetStdHandle(-11), 7)
            return True
        except Exception:
            return False
    return True


_USE_COLOR = _ansi_supported()

RED     = '\033[91m' if _USE_COLOR else ''
GREEN   = '\033[92m' if _USE_COLOR else ''
YELLOW  = '\033[93m' if _USE_COLOR else ''
CYAN    = '\033[96m' if _USE_COLOR else ''
WHITE   = '\033[97m' if _USE_COLOR else ''
DIM     = '\033[2m'  if _USE_COLOR else ''
RESET   = '\033[0m'  if _USE_COLOR else ''


_LOGO = rf"""
{RED} ██╗    ██╗ ██████╗ ██████╗ ███╗   ███╗{RESET}{WHITE}███████╗████████╗██████╗ ██╗██╗  ██╗███████╗{RESET}
{RED} ██║    ██║██╔═══██╗██╔══██╗████╗ ████║{RESET}{WHITE}██╔════╝╚══██╔══╝██╔══██╗██║██║ ██╔╝██╔════╝{RESET}
{RED} ██║ █╗ ██║██║   ██║██████╔╝██╔████╔██║{RESET}{WHITE}███████╗   ██║   ██████╔╝██║█████╔╝ █████╗  {RESET}
{RED} ██║███╗██║██║   ██║██╔══██╗██║╚██╔╝██║{RESET}{WHITE}╚════██║   ██║   ██╔══██╗██║██╔═██╗ ██╔══╝  {RESET}
{RED} ╚███╔███╔╝╚██████╔╝██║  ██║██║ ╚═╝ ██║{RESET}{WHITE}███████║   ██║   ██║  ██║██║██║  ██╗███████╗{RESET}
{RED}  ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝{RESET}{WHITE}╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝{RESET}
"""

G  = '\033[32m'  if _USE_COLOR else ''   # dark green (body segments)
BG = '\033[92m'  if _USE_COLOR else ''   # bright green (head)

# ── Earthworm striking a host ─────────────────────────────────────────────
#
# Visual layout (54 chars before the target box):
#
#  col:  0         1         2         3         4         5
#        0123456789012345678901234567890123456789012345678901234
#  L1:   [54 spaces]                                    .-----------.
#  L2:     .-.  .-.  .-.  .-.  .-.  .-.  .-.  .-~~~.   |  [TARGET] |
#  L3:     (   )(   )(   )(   )(   )(   )(   )( >=>)>===---->> |   [x_x]   |
#  L4:     `-'  `-'  `-'  `-'  `-'  `-'  `-'  `~~~~~'  |           |
#  L5:   [54 spaces]                                    `-----------'
#
# Worm-top   (43 chars): "  " + "  ".join([".-."] * 7) + "  " + ".-~~~."
# Worm-body  (43 chars): "  " + "(   )" * 7 + "( >=>)"
# Worm-bot   (44 chars): "  " + "  ".join(["`-'"] * 7) + "  " + "`~~~~~'"
# Arrow      (11 chars): ">===---->>  "
# Box col    starts at 54

_PAD = 54

def _c(raw: str, color: str) -> str:
    """Wrap raw text in a colour, reset after."""
    return f"{color}{raw}{RESET}"

def _worm_art() -> str:
    # Body segments
    seg_tops = "  ".join([".-."] * 7)       # 33 chars
    seg_bods = "".join(["(   )"] * 7)        # 35 chars
    seg_bots = "  ".join(["`-'"] * 7)        # 33 chars

    # Coloured pieces
    c_seg_tops = "  ".join([_c(".-.", G)]  * 7)
    c_seg_bods = "".join([_c("(   )", G)]  * 7)
    c_seg_bots = "  ".join([_c("`-'", G)]  * 7)

    c_htop  = _c(".-~~~.", BG)
    c_hbod  = _c("( >=>)", BG)
    c_hbot  = _c("`~~~~~'", BG)
    c_arrow = _c(">===---->", RED) + _c(">", YELLOW)

    # Target box — all rows must be exactly 14 visible chars
    #   .------------.    14 = . + 12 dashes + .
    #   | [ TARGET ] |    14 = |+sp+[TARGET]+sp+|
    #   |  \(x_x)/  |    14 = |+2sp+7+3sp+|      (wait: 1+2+7+3+1=14) ✓
    #   |   ( | | ) |    14 = |+3sp+7+2sp+|      (1+3+7+2+1=14)       ✓
    #   `------------'   14 = ` + 12 dashes + '
    tb_top   = f"{WHITE}.------------.{RESET}"
    tb_l1    = f"{WHITE}| {RESET}{RED}[ TARGET ]{RESET}{WHITE} |{RESET}"
    tb_l2    = f"{WHITE}|  {RESET}{DIM}\\(x_x)/{RESET}{WHITE}   |{RESET}"
    tb_l3    = f"{WHITE}|   {RESET}{DIM}( | | ){RESET}{WHITE}  |{RESET}"
    tb_bot   = f"{WHITE}`------------'{RESET}"

    # Worm line visual lengths (without ANSI):
    # top:  2 + 33 + 2 + 6  = 43
    # body: 2 + 35 + 6       = 43
    # bot:  2 + 33 + 2 + 7  = 44
    # arrow: 10 chars  → body+arrow = 53, pad to 54 with 1 space then box

    sp = _PAD - 43         # = 11 spaces after worm top/body to reach col 54
    sp_bot = _PAD - 44     # = 10 spaces after worm bot

    lines = [
        " " * _PAD                                              + tb_top,
        "  " + c_seg_tops + "  " + c_htop + " " * sp           + tb_l1,
        "  " + c_seg_bods + c_hbod + c_arrow + " "             + tb_l2,
        "  " + c_seg_bots + "  " + c_hbot + " " * sp_bot       + tb_l3,
        " " * _PAD                                              + tb_bot,
    ]
    return "\n".join(lines)


_TAGLINE = (
    f"  {DIM}┌{'─'*68}┐{RESET}\n"
    f"  {DIM}│{RESET}  {CYAN}CrowdStrike Falcon deployment & endpoint discovery tool{RESET}"
    + " " * 13
    + f"{DIM}│{RESET}\n"
    f"  {DIM}│{RESET}  {DIM}Detect · Download · Deploy · Propagate{RESET}"
    + " " * 28
    + f"{DIM}│{RESET}\n"
    f"  {DIM}└{'─'*68}┘{RESET}"
)


def print_banner():
    print(_LOGO)
    print(_worm_art())
    print()
    print(_TAGLINE)
    print()
