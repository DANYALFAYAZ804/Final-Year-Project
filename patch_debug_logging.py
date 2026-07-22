"""
Adds temporary debug logging to every `except SQLAlchemyError:` block
in backend/app.py, so the real database error prints to Railway logs
instead of being silently swallowed.

Usage:
    python patch_debug_logging.py
"""

import re

FILE = "backend/app.py"

with open(FILE, "r", encoding="utf-8") as f:
    content = f.read()

# Matches "except SQLAlchemyError:" capturing its leading whitespace,
# and inserts a debug print line right after it with +4 space indent.
pattern = re.compile(r"^([ \t]*)except SQLAlchemyError:\n", re.MULTILINE)

def replacer(match):
    indent = match.group(1)
    inner_indent = indent + "    "
    return (
        f"{indent}except SQLAlchemyError as e:\n"
        f'{inner_indent}print(f"[DEBUG DB ERROR] {{type(e).__name__}}: {{e}}")\n'
    )

new_content, count = pattern.subn(replacer, content)

with open(FILE, "w", encoding="utf-8") as f:
    f.write(new_content)

print(f"Patched {count} exception handler(s) in {FILE}.")
