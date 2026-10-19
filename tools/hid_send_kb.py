#!/usr/bin/env python3
"""Standalone PS5 HID keyboard sender with inline sequence.

A self-contained version of hid_navigate.py that includes its own
key sequence (no external import needed). Useful for quick one-off
navigation or as a template for custom sequences.

Usage:
    python3 hid_send_kb.py --device /dev/hidg0
"""
import argparse
import time
import sys

KEY_CODES = {
    'ENTER': 0x28,
    'ESC': 0x29,
    'BACKSPACE': 0x2a,
    'TAB': 0x2b,
    'SPACE': 0x2c,
    'UP': 0x52,
    'DOWN': 0x51,
    'RIGHT': 0x4f,
    'LEFT': 0x50,
    'PAGE_UP': 0x4b,
    'PAGE_DOWN': 0x4e,
    'A': 0x04, 'B': 0x05, 'C': 0x06, 'D': 0x07,
    'E': 0x08, 'F': 0x09, 'G': 0x0a, 'H': 0x0b,
    'I': 0x0c, 'J': 0x0d, 'K': 0x0e, 'L': 0x0f,
    'M': 0x10, 'N': 0x11, 'O': 0x12, 'P': 0x13,
    'Q': 0x14, 'R': 0x15, 'S': 0x16, 'T': 0x17,
    'U': 0x18, 'V': 0x19, 'W': 0x1a, 'X': 0x1b,
    'Y': 0x1c, 'Z': 0x1d,
}

SEQUENCE = [
    (0.000, 'ENTER'),
    (9.000, 'ENTER'),
    (2.996, 'ENTER'),
    (3.000, 'UP'),
    (0.241, 'RIGHT'),
    (0.29,  'RIGHT'),
    (0.339, 'RIGHT'),
    (0.553, 'ENTER'),
    (1.902, 'UP'),
    (0.353, 'UP'),
    (0.382, 'ENTER'),
    (1.107, 'ENTER'),
    (0.761, 'ENTER'),
    (2.723, 'ENTER'),
]


def send_key(hid, keycode, modifier=0):
    press = bytes([modifier, 0, keycode, 0, 0, 0, 0, 0])
    release = bytes([0, 0, 0, 0, 0, 0, 0, 0])
    hid.write(press)
    hid.flush()
    time.sleep(0.05)
    hid.write(release)
    hid.flush()


def countdown(seconds, next_key):
    if seconds <= 0:
        return
    step = 0.1
    remaining = seconds
    while remaining > 0:
        sys.stdout.write(f"\r  next key '{next_key}' in {remaining:4.1f}s ")
        sys.stdout.flush()
        sleep_time = min(step, remaining)
        time.sleep(sleep_time)
        remaining -= sleep_time
    sys.stdout.write("\r" + " " * 30 + "\r")
    sys.stdout.flush()


def main():
    parser = argparse.ArgumentParser(description="PS5 HID keyboard sender (standalone)")
    parser.add_argument("--device", default="/dev/hidg0", help="HID gadget device (default: /dev/hidg0)")
    args = parser.parse_args()

    print("Starting PS5 menu navigation...")
    with open(args.device, 'wb', buffering=0) as hid:
        for delay, key_name in SEQUENCE:
            countdown(delay, key_name)
            keycode = KEY_CODES[key_name]
            send_key(hid, keycode)
            print(f"Sent key: {key_name}")
    print("Navigation complete.")


if __name__ == '__main__':
    main()
