#!/usr/bin/env python3
import serial
import readline

def interactive_shell(port):
    with serial.Serial(port, 115200, timeout=1) as ser:
        while True:
            cmd = input("kobe> ")
            ser.write(f"{cmd}\n".encode())
            print(ser.read(1024).decode())

if __name__ == "__main__":
    interactive_shell("/dev/ttyACM0")