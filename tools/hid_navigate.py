#!/usr/bin/env python3
"""USB HID keyboard emulation for headless PS5 navigation.

Sends timed key sequences to a USB HID gadget device to navigate
the PS5 UI without HDMI output. Requires Linux USB gadget mode
with a HID keyboard function configured on the host.

Usage:
    python3 hid_navigate.py --device /dev/hidg0
"""
import argparse
import time
import sys
from hid_nav_sequence import KEY_CODES, SEQUENCE


def make_logger(log_path):
    def log(msg):
        with open(log_path, 'a') as f:
            f.write(msg + '\n')
        print(msg)
    return log


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
    parser = argparse.ArgumentParser(description="PS5 HID keyboard navigation")
    parser.add_argument("--device", default="/dev/hidg0", help="HID gadget device (default: /dev/hidg0)")
    parser.add_argument("--log", default="/tmp/nav_log.txt", help="Log file path")
    args = parser.parse_args()

    log = make_logger(args.log)
    log("Starting PS5 menu navigation...")
    with open(args.device, 'wb', buffering=0) as hid:
        for delay, key_name in SEQUENCE:
            countdown(delay, key_name)
            keycode = KEY_CODES[key_name]
            send_key(hid, keycode)
            log(f"[{time.strftime('%H:%M:%S')}] Sent key: {key_name}")
    log("Navigation complete.")


if __name__ == '__main__':
    main()
