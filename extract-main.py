import argparse
import re
import io
import contextlib
import logging
import tempfile
from typing import Union, Optional, List, Set
from pathlib import Path

# Note: pip install uefi_firmware
try:
    from uefi_firmware import AutoParser
except ImportError:
    print("Error: 'uefi_firmware' library not found. Install it via: pip install uefi_firmware")
    exit(1)

BL_MAGIC_PATTERNS = [
    bytes.fromhex('4D 5A'),                     # MZ → PE/COFF (EFI)
    bytes.fromhex('7F 45 4C 46'),               # ELF
    bytes.fromhex('88 16 88 58'),               # Little Kernel (some versions)
    bytes.fromhex('46 42 50 4B'),               # FBPK (some MediaTek)
    bytes.fromhex('44 48 54 42'),               # DHTB (some MediaTek signed)
    bytes.fromhex('41 4E 44 52 4F 49 44 21'),   # ANDROID! (some second stage)
]

def setup_logging() -> logging.Logger:
    class PrefixFormatter(logging.Formatter):
        def format(self, record):
            record.msg = f"(x) {record.msg}"
            return super().format(record)

    log = logging.getLogger('fastboot-command-extractor')
    log.setLevel(logging.INFO)
    log.propagate = False
    handler = logging.StreamHandler()
    handler.setFormatter(PrefixFormatter('%(message)s'))
    log.addHandler(handler)
    return log

logger = setup_logging()


def find_fastboot_commands(data: bytes, filename: str = "") -> List[str]:
    """
    Extract potential fastboot commands from binary data.
    Returns list of command strings ready to print.
    """
    found: Set[str] = set()

    # ── 1. OEM commands ───────────────────────────────────────────────────────
    # Looking for:  oem something   or   fastboot oem something
    oem_patterns = [
        rb'(?:fastboot\s+)?oem\s+([^\x00\s\n\r<>{}[\]()]{1,80})(?:\x00|\s|$)',
        rb'oem\s+([a-zA-Z0-9_-]{2,60})(?:\x00|\s|$)',
    ]

    for pat in oem_patterns:
        for match in re.finditer(pat, data, re.IGNORECASE):
            cmd_part = match.group(1).decode('ascii', errors='ignore').strip()
            if cmd_part and 1 <= len(cmd_part.split()) <= 6:
                if not any(c in cmd_part for c in '<>[]{}'):
                    full = f"fastboot oem {cmd_part}"
                    found.add(full)

    # ── 2. Standard / protocol-level fastboot commands ────────────────────────
    standard_patterns = [
        # Most common commands people actually use
        rb'(flash|erase|boot|reboot|continue|download|upload|getvar|flashing|set_active)\b',
        # Slightly longer / more specific patterns
        rb'(flash|erase)\s+[a-z0-9_-]{2,30}\b',
        rb'reboot(?:-bootloader|-recovery|-fastboot|-edl)?\b',
        rb'getvar\s+(?:all|version|current-slot|slot-count|frp-state|secure|anti)\b',
        rb'flashing\s+(lock|unlock|lock_critical|unlock_critical)\b',
        rb'set_active\s+[a|b|_a|_b]\b',
        rb'flashall|flash:.*|erase:.*',
        rb'oem (?:help|\?|info|device-info)',
        rb'(?:reboot|oem|edl)\s*(?:edl|-edl)?\b',
rb'fastboot\s+edl\b',
rb'oem\s+edl\b',
rb'reboot-edl\b',
rb'edl\b',  # last resort, but noisy
    ]

    for pat in standard_patterns:
        for match in re.finditer(pat, data, re.IGNORECASE):
            text = match.group(0).decode('ascii', errors='ignore').strip()
            if not text:
                continue

            # Try to normalize into command form
            lower = text.lower()

            if lower.startswith(('flash ', 'erase ', 'flashing ', 'getvar ', 'set_active ')):
                full = f"fastboot {text}"
                found.add(full)
            elif lower in {'boot', 'continue', 'reboot', 'reboot-bootloader', 'reboot-recovery', 'reboot-edl'}:
                full = f"fastboot {text}"
                found.add(full)
            elif lower.startswith('oem '):
                full = f"fastboot {text}"
                found.add(full)

    # Remove very short / noisy matches
    cleaned = [c for c in found if len(c) > 12 and ' ' in c]

    if cleaned and filename:
        logger.info(f"Found {len(cleaned)} potential fastboot commands in: {filename}")

    return sorted(set(cleaned))


def extract_from_file(firmware_path: Path) -> int:
    """Try different extraction strategies on one file"""
    total_found = 0

    try:
        raw = firmware_path.read_bytes()
    except Exception as e:
        logger.error(f"Cannot read {firmware_path}: {e}")
        return 0

    # Strategy 1: Direct string search on whole file
    cmds = find_fastboot_commands(raw, firmware_path.name)
    if cmds:
        print("\n".join(cmds))
        total_found += len(cmds)

    # Strategy 2: Look for embedded PE/UEFI images
    pe_offsets = [m.start() for m in re.finditer(b'MZ', raw)]
    if pe_offsets:
        logger.info(f"Found {len(pe_offsets)} possible embedded PE signatures")
        for i, start in enumerate(pe_offsets[:30]):  # limit to avoid too many
            end = pe_offsets[i + 1] if i + 1 < len(pe_offsets) else len(raw)
            segment = raw[start:end]
            if len(segment) < 4096:
                continue
            sub_cmds = find_fastboot_commands(segment, f"{firmware_path.name} @ 0x{start:x}")
            if sub_cmds:
                print("\n".join(sub_cmds))
                total_found += len(sub_cmds)

    return total_found


def try_uefi_parsing(data: bytes, name: str) -> int:
    count = 0
    max_tries = min(len(data) // 2048, 80)

    for i in range(max_tries):
        offset = i * 2048
        try:
            parser = AutoParser(data[offset:])
            if parser.type() == 'unknown':
                continue

            logger.info(f"Detected UEFI structure at offset 0x{offset:x}")

            with tempfile.TemporaryDirectory() as tmp:
                with contextlib.redirect_stdout(io.StringIO()):
                    parsed = parser.parse()
                    if parsed:
                        parsed.dump(tmp)
                for pe in Path(tmp).rglob("*.[pP][eE]"):
                    try:
                        cmds = find_fastboot_commands(pe.read_bytes(), pe.name)
                        if cmds:
                            print("\n".join(cmds))
                            count += len(cmds)
                    except:
                        pass
            if count > 0:
                return count
        except:
            pass

    return count


def main():
    parser = argparse.ArgumentParser(
        description='Extract hidden fastboot commands (oem + standard) from firmware/bootloader files'
    )
    parser.add_argument('file', type=str, help='firmware / bootloader file to analyze')
    parser.add_argument('--force', '-f', action='store_true',
                        help='force deep string search even on unknown formats')
    args = parser.parse_args()

    path = Path(args.file)
    if not path.is_file():
        logger.error(f"File not found: {path}")
        exit(1)

    logger.info(f"Fastboot Command Extractor by ROM2box")

    total = 0

    # Try UEFI style parsing first (many abl.elf, boot.img second stage, etc.)
    try:
        with open(path, 'rb') as f:
            head = f.read(10 * 1024 * 1024)
        uefi_count = try_uefi_parsing(head, path.name)
        total += uefi_count
    except Exception as e:
        logger.debug(f"UEFI parsing failed: {e}")

    # Fallback / main path: direct + embedded PE search
    direct_count = extract_from_file(path)
    total += direct_count

    if total == 0 and args.force:
        logger.info("No commands found → running force string extraction")
        raw = path.read_bytes()
        cmds = find_fastboot_commands(raw, path.name)
        if cmds:
            print("\n".join(cmds))
            total += len(cmds)

    if total == 0:
        logger.warning("No fastboot commands found in this file.")
        exit(1)
    else:
        logger.info(f"Total potential commands found: {total}")


if __name__ == '__main__':
    main()