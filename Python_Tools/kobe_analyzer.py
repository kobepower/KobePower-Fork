#!/usr/bin/env python3
import serial
import matplotlib.pyplot as plt

def plot_signal(port):
    with serial.Serial(port, 115200, timeout=1) as ser:
        ser.write(b"analyze\n")
        data = ser.read(1024).decode()
        rssi = int(data.split("RSSI ")[1].split(",")[0])
        noise = int(data.split("Noise ")[1].split("\n")[0])
        plt.bar(["RSSI", "Noise"], [rssi, noise])
        plt.show()

if __name__ == "__main__":
    plot_signal("/dev/ttyACM0")