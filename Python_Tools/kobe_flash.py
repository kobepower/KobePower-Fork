#!/usr/bin/env python3
import serial
import sys

def flash_firmware(port, firmware_path):
    with serial.Serial(port, 115200, timeout=1) as ser, open(firmware_path, 'rb') as f:
        firmware = f.read()
        ser.write(f"update {len(firmware)}\n".encode())
        ser.write(firmware)
        print(ser.read(1024).decode())

if __name__ == "__main__":
    flash_firmware(sys.argv[1], sys.argv[2])