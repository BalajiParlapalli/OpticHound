#!/usr/bin/env python3
"""
OpticHound - Rental Stay Hidden Camera & Surveillance Device Detector
Cross-Platform Network Scanner for Linux, macOS, and Windows.

Detects hidden cameras, NVRs/DVRs, RTSP streams, ONVIF services,
surveillance web dashboards, and IoT camera chipsets on local Wi-Fi.
Scores devices by risk and generates terminal and interactive HTML reports.
"""

import sys
import os
import re
import time
import socket
import struct
import select
import urllib.request
import urllib.error
import urllib.parse
import ssl
import json
import argparse
import platform
import subprocess
import ipaddress
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Any

# Ensure UTF-8 output on Windows consoles
if sys.platform.startswith("win"):
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Graceful optional package imports
HAVE_SCAPY = False
try:
    from scapy.all import arping, srp, Ether, ARP
    HAVE_SCAPY = True
except Exception:
    pass

HAVE_ZEROCONF = False
try:
    import zeroconf
    HAVE_ZEROCONF = True
except Exception:
    pass

HAVE_COLORAMA = False
try:
    import colorama
    colorama.init(autoreset=True)
    HAVE_COLORAMA = True
except Exception:
    pass

# ---------------------------------------------------------------------------
# ANSI Terminal Colors
# ---------------------------------------------------------------------------
class Colors:
    def __init__(self, enabled=True):
        self.enabled = enabled and sys.stdout.isatty() and not os.environ.get("NO_COLOR")

    def _c(self, code: str) -> str:
        return code if self.enabled else ""

    @property
    def RESET(self): return self._c("\033[0m")
    @property
    def BOLD(self): return self._c("\033[1m")
    @property
    def DIM(self): return self._c("\033[2m")
    @property
    def RED(self): return self._c("\033[91m")
    @property
    def GREEN(self): return self._c("\033[92m")
    @property
    def YELLOW(self): return self._c("\033[93m")
    @property
    def BLUE(self): return self._c("\033[94m")
    @property
    def MAGENTA(self): return self._c("\033[95m")
    @property
    def CYAN(self): return self._c("\033[96m")
    @property
    def WHITE(self): return self._c("\033[97m")
    @property
    def BG_RED(self): return self._c("\033[41m\033[97m\033[1m")
    @property
    def BG_YELLOW(self): return self._c("\033[43m\033[30m\033[1m")
    @property
    def BG_GREEN(self): return self._c("\033[42m\033[30m\033[1m")

# Global colors instance
C = Colors(enabled=True)

# ---------------------------------------------------------------------------
# Built-in Surveillance & IoT MAC OUI Database
# Maps prefix (lowercase 6 hex chars) -> (Vendor Name, Category, Risk Weight)
# Categories: 'CAM_BRAND', 'IOT_CHIP', 'SMART_DISPLAY', 'BENIGN'
# ---------------------------------------------------------------------------
OUI_DATABASE = {
    # Hikvision (Hangzhou Hikvision Digital Technology)
    "001212": ("Hangzhou Hikvision Digital Technology", "CAM_BRAND", 35),
    "00182a": ("Hangzhou Hikvision Digital Technology", "CAM_BRAND", 35),
    "08a189": ("Hangzhou Hikvision Digital Technology", "CAM_BRAND", 35),
    "10da43": ("Hangzhou Hikvision Digital Technology", "CAM_BRAND", 35),
    "14b484": ("Hangzhou Hikvision Digital Technology", "CAM_BRAND", 35),
    "1868cb": ("Hangzhou Hikvision Digital Technology", "CAM_BRAND", 35),
    "24e6ba": ("Hangzhou Hikvision Digital Technology", "CAM_BRAND", 35),
    "2cd724": ("Hangzhou Hikvision Digital Technology", "CAM_BRAND", 35),
    "34b354": ("Hangzhou Hikvision Digital Technology", "CAM_BRAND", 35),
    "3c1b9d": ("Hangzhou Hikvision Digital Technology", "CAM_BRAND", 35),
    "40163b": ("Hangzhou Hikvision Digital Technology", "CAM_BRAND", 35),
    "4419b6": ("Hangzhou Hikvision Digital Technology", "CAM_BRAND", 35),
    "4447cc": ("Hangzhou Hikvision Digital Technology", "CAM_BRAND", 35),
    "4cbd8f": ("Hangzhou Hikvision Digital Technology", "CAM_BRAND", 35),
    "500959": ("Hangzhou Hikvision Digital Technology", "CAM_BRAND", 35),
    "542696": ("Hangzhou Hikvision Digital Technology", "CAM_BRAND", 35),
    "54c415": ("Hangzhou Hikvision Digital Technology", "CAM_BRAND", 35),
    "5803fb": ("Hangzhou Hikvision Digital Technology", "CAM_BRAND", 35),
    "5ce91e": ("Hangzhou Hikvision Digital Technology", "CAM_BRAND", 35),
    "609c9f": ("Hangzhou Hikvision Digital Technology", "CAM_BRAND", 35),
    "64db8b": ("Hangzhou Hikvision Digital Technology", "CAM_BRAND", 35),
    "686dbc": ("Hangzhou Hikvision Digital Technology", "CAM_BRAND", 35),
    "70af6a": ("Hangzhou Hikvision Digital Technology", "CAM_BRAND", 35),
    "7404f1": ("Hangzhou Hikvision Digital Technology", "CAM_BRAND", 35),
    "74a78e": ("Hangzhou Hikvision Digital Technology", "CAM_BRAND", 35),
    "807b3e": ("Hangzhou Hikvision Digital Technology", "CAM_BRAND", 35),
    "849a40": ("Hangzhou Hikvision Digital Technology", "CAM_BRAND", 35),
    "88e7a6": ("Hangzhou Hikvision Digital Technology", "CAM_BRAND", 35),
    "8ce748": ("Hangzhou Hikvision Digital Technology", "CAM_BRAND", 35),
    "94e1ac": ("Hangzhou Hikvision Digital Technology", "CAM_BRAND", 35),
    "988b5d": ("Hangzhou Hikvision Digital Technology", "CAM_BRAND", 35),
    "9c1463": ("Hangzhou Hikvision Digital Technology", "CAM_BRAND", 35),
    "a0bdcd": ("Hangzhou Hikvision Digital Technology", "CAM_BRAND", 35),
    "a41437": ("Hangzhou Hikvision Digital Technology", "CAM_BRAND", 35),
    "ac8ba9": ("Hangzhou Hikvision Digital Technology", "CAM_BRAND", 35),
    "b4a382": ("Hangzhou Hikvision Digital Technology", "CAM_BRAND", 35),
    "b8eca3": ("Hangzhou Hikvision Digital Technology", "CAM_BRAND", 35),
    "bc15ac": ("Hangzhou Hikvision Digital Technology", "CAM_BRAND", 35),
    "bc5436": ("Hangzhou Hikvision Digital Technology", "CAM_BRAND", 35),
    "c056e3": ("Hangzhou Hikvision Digital Technology", "CAM_BRAND", 35),
    "c8028f": ("Hangzhou Hikvision Digital Technology", "CAM_BRAND", 35),
    "ccb927": ("Hangzhou Hikvision Digital Technology", "CAM_BRAND", 35),
    "d05ba8": ("Hangzhou Hikvision Digital Technology", "CAM_BRAND", 35),
    "d46e0e": ("Hangzhou Hikvision Digital Technology", "CAM_BRAND", 35),
    "dcf756": ("Hangzhou Hikvision Digital Technology", "CAM_BRAND", 35),
    "e0508b": ("Hangzhou Hikvision Digital Technology", "CAM_BRAND", 35),
    "e472e2": ("Hangzhou Hikvision Digital Technology", "CAM_BRAND", 35),
    "ec74e7": ("Hangzhou Hikvision Digital Technology", "CAM_BRAND", 35),
    "f84dfc": ("Hangzhou Hikvision Digital Technology", "CAM_BRAND", 35),
    "fc3342": ("Hangzhou Hikvision Digital Technology", "CAM_BRAND", 35),
    "fcd5b7": ("Hangzhou Hikvision Digital Technology", "CAM_BRAND", 35),

    # Dahua (Zhejiang Dahua Technology)
    "001a07": ("Zhejiang Dahua Technology", "CAM_BRAND", 35),
    "14a78b": ("Zhejiang Dahua Technology", "CAM_BRAND", 35),
    "2857be": ("Zhejiang Dahua Technology", "CAM_BRAND", 35),
    "38af29": ("Zhejiang Dahua Technology", "CAM_BRAND", 35),
    "3cef8c": ("Zhejiang Dahua Technology", "CAM_BRAND", 35),
    "4024b2": ("Zhejiang Dahua Technology", "CAM_BRAND", 35),
    "4c11bf": ("Zhejiang Dahua Technology", "CAM_BRAND", 35),
    "50ec50": ("Zhejiang Dahua Technology", "CAM_BRAND", 35),
    "6c8dc1": ("Zhejiang Dahua Technology", "CAM_BRAND", 35),
    "78321b": ("Zhejiang Dahua Technology", "CAM_BRAND", 35),
    "7c03d8": ("Zhejiang Dahua Technology", "CAM_BRAND", 35),
    "84b499": ("Zhejiang Dahua Technology", "CAM_BRAND", 35),
    "9002a9": ("Zhejiang Dahua Technology", "CAM_BRAND", 35),
    "a0bd1d": ("Zhejiang Dahua Technology", "CAM_BRAND", 35),
    "ac61ea": ("Zhejiang Dahua Technology", "CAM_BRAND", 35),
    "bc32ac": ("Zhejiang Dahua Technology", "CAM_BRAND", 35),
    "bcbae1": ("Zhejiang Dahua Technology", "CAM_BRAND", 35),
    "d46e5c": ("Zhejiang Dahua Technology", "CAM_BRAND", 35),
    "d896e0": ("Zhejiang Dahua Technology", "CAM_BRAND", 35),
    "ec71db": ("Zhejiang Dahua Technology", "CAM_BRAND", 35),
    "f4b85e": ("Zhejiang Dahua Technology", "CAM_BRAND", 35),

    # Wyze Labs
    "2caa8e": ("Wyze Labs Inc", "CAM_BRAND", 35),
    "2caa8f": ("Wyze Labs Inc", "CAM_BRAND", 35),
    "7c78b2": ("Wyze Labs Inc", "CAM_BRAND", 35),
    "a4da22": ("Wyze Labs Inc", "CAM_BRAND", 35),
    "d03f27": ("Wyze Labs Inc", "CAM_BRAND", 35),
    "5c0270": ("Wyze Labs Inc", "CAM_BRAND", 35),
    "60a423": ("Wyze Labs Inc", "CAM_BRAND", 35),

    # Ring LLC / Amazon Surveillance
    "0c47c9": ("Ring LLC", "CAM_BRAND", 30),
    "18742e": ("Ring LLC", "CAM_BRAND", 30),
    "244ce3": ("Ring LLC", "CAM_BRAND", 30),
    "343ea4": ("Ring LLC", "CAM_BRAND", 30),
    "3c5a37": ("Ring LLC", "CAM_BRAND", 30),
    "44650d": ("Ring LLC", "CAM_BRAND", 30),
    "50f5da": ("Ring LLC", "CAM_BRAND", 30),
    "54e019": ("Ring LLC", "CAM_BRAND", 30),
    "6837e9": ("Ring LLC / Amazon Blink", "CAM_BRAND", 30),
    "68545a": ("Ring LLC", "CAM_BRAND", 30),
    "74c246": ("Ring LLC", "CAM_BRAND", 30),
    "78e103": ("Ring LLC", "CAM_BRAND", 30),
    "8871e5": ("Ring LLC", "CAM_BRAND", 30),
    "8c8590": ("Ring LLC", "CAM_BRAND", 30),
    "949aa9": ("Ring LLC", "CAM_BRAND", 30),
    "a002dc": ("Ring LLC", "CAM_BRAND", 30),
    "b009da": ("Ring LLC", "CAM_BRAND", 30),
    "c4823f": ("Ring LLC", "CAM_BRAND", 30),
    "ccf411": ("Ring LLC", "CAM_BRAND", 30),
    "d4a651": ("Ring LLC", "CAM_BRAND", 30),
    "e09d31": ("Ring LLC", "CAM_BRAND", 30),
    "fc65de": ("Ring LLC", "CAM_BRAND", 30),

    # Arlo Technologies
    "2c3033": ("Arlo Technologies", "CAM_BRAND", 35),
    "30469a": ("Arlo Technologies", "CAM_BRAND", 35),
    "48a6b8": ("Arlo Technologies", "CAM_BRAND", 35),
    "54be53": ("Arlo Technologies", "CAM_BRAND", 35),
    "7898e8": ("Arlo Technologies", "CAM_BRAND", 35),
    "9c3dcf": ("Arlo Technologies", "CAM_BRAND", 35),
    "a00460": ("Arlo Technologies / Netgear", "CAM_BRAND", 35),
    "c40415": ("Arlo Technologies", "CAM_BRAND", 35),
    "e4f042": ("Arlo Technologies", "CAM_BRAND", 35),

    # Reolink / Shenzhen Reolink Technology
    "002494": ("Shenzhen Reolink Technology", "CAM_BRAND", 35),
    "e0dcff": ("Shenzhen Reolink Technology", "CAM_BRAND", 35),
    "3808fd": ("Shenzhen Reolink Technology", "CAM_BRAND", 35),
    "649a12": ("Shenzhen Reolink Technology", "CAM_BRAND", 35),

    # Axis Communications
    "00408c": ("Axis Communications", "CAM_BRAND", 35),
    "accc8e": ("Axis Communications", "CAM_BRAND", 35),
    "b8a44f": ("Axis Communications", "CAM_BRAND", 35),
    "e82725": ("Axis Communications", "CAM_BRAND", 35),

    # Foscam (Shenzhen Foscam Intelligent Technology)
    "00626e": ("Shenzhen Foscam Intelligent Tech", "CAM_BRAND", 35),
    "48022a": ("Shenzhen Foscam Intelligent Tech", "CAM_BRAND", 35),
    "000ec6": ("Shenzhen Foscam Intelligent Tech", "CAM_BRAND", 35),
    "c80e77": ("Shenzhen Foscam Intelligent Tech", "CAM_BRAND", 35),

    # Amcrest Technologies
    "9c8ecd": ("Amcrest Technologies", "CAM_BRAND", 35),

    # Eufy / Anker Innovations Security
    "286d97": ("Anker / Eufy Security", "CAM_BRAND", 30),
    "70b3d5": ("Anker / Eufy Security", "CAM_BRAND", 30),
    "9884e3": ("Anker / Eufy Security", "CAM_BRAND", 30),
    "a4c138": ("Anker / Eufy Security", "CAM_BRAND", 30),
    "c8ff77": ("Anker / Eufy Security", "CAM_BRAND", 30),

    # Yi Technology / Shanghai Xiaoyi
    "4849c7": ("Shanghai Xiaoyi / Yi Technology", "CAM_BRAND", 35),
    "7811dc": ("Shanghai Xiaoyi / Yi Technology", "CAM_BRAND", 35),
    "f0b429": ("Shanghai Xiaoyi / Yi Technology", "CAM_BRAND", 35),
    "7c49eb": ("Shanghai Xiaoyi / Yi Technology", "CAM_BRAND", 35),
    "44237c": ("Shanghai Xiaoyi / Yi Technology", "CAM_BRAND", 35),

    # Blink / Immedia Semiconductor
    "f08173": ("Blink / Immedia Semiconductor", "CAM_BRAND", 35),
    "b87f3b": ("Blink / Immedia Semiconductor", "CAM_BRAND", 35),

    # Hanwha / Samsung Techwin
    "000918": ("Hanwha Techwin / Samsung Techwin", "CAM_BRAND", 35),
    "00166c": ("Hanwha Techwin / Samsung Techwin", "CAM_BRAND", 35),
    "0024e9": ("Hanwha Techwin / Samsung Techwin", "CAM_BRAND", 35),

    # Xiongmai / Hangzhou Xiongmai Technology (Core of OEM Chinese Spy Cams)
    "001215": ("Hangzhou Xiongmai Technology", "CAM_BRAND", 40),
    "001216": ("Hangzhou Xiongmai Technology", "CAM_BRAND", 40),
    "001217": ("Hangzhou Xiongmai Technology", "CAM_BRAND", 40),
    "001218": ("Hangzhou Xiongmai Technology", "CAM_BRAND", 40),
    "002363": ("Hangzhou Xiongmai Technology", "CAM_BRAND", 40),
    "1012fb": ("Hangzhou Xiongmai Technology", "CAM_BRAND", 40),
    "48ea63": ("Hangzhou Xiongmai Technology", "CAM_BRAND", 40),
    "f81a67": ("Hangzhou Xiongmai Technology", "CAM_BRAND", 40),

    # Ubiquiti Networks (UniFi Protect Cameras)
    "002722": ("Ubiquiti Networks", "CAM_BRAND", 25),
    "0418d6": ("Ubiquiti Networks", "CAM_BRAND", 25),
    "18e829": ("Ubiquiti Networks", "CAM_BRAND", 25),
    "245a4c": ("Ubiquiti Networks", "CAM_BRAND", 25),
    "24a43c": ("Ubiquiti Networks", "CAM_BRAND", 25),
    "44d9e7": ("Ubiquiti Networks", "CAM_BRAND", 25),
    "68d79a": ("Ubiquiti Networks", "CAM_BRAND", 25),
    "7483c2": ("Ubiquiti Networks", "CAM_BRAND", 25),
    "784558": ("Ubiquiti Networks", "CAM_BRAND", 25),
    "788a20": ("Ubiquiti Networks", "CAM_BRAND", 25),
    "802aa8": ("Ubiquiti Networks", "CAM_BRAND", 25),
    "b4fbe4": ("Ubiquiti Networks", "CAM_BRAND", 25),
    "dc9fdb": ("Ubiquiti Networks", "CAM_BRAND", 25),
    "e063da": ("Ubiquiti Networks", "CAM_BRAND", 25),
    "fcecda": ("Ubiquiti Networks", "CAM_BRAND", 25),

    # Google / Nest Labs
    "18b430": ("Google Nest Labs", "CAM_BRAND", 25),
    "641666": ("Google Nest Labs", "CAM_BRAND", 25),
    "d86c63": ("Google Nest Labs", "CAM_BRAND", 25),
    "f4f5db": ("Google Nest Labs", "CAM_BRAND", 25),
    "f40343": ("Google Nest Labs", "CAM_BRAND", 25),
    "40b4cd": ("Google Nest Labs", "CAM_BRAND", 25),
    "a47733": ("Google Nest Labs", "CAM_BRAND", 25),

    # Luxottica (Ray-Ban Meta / Ray-Ban Stories Smart Glasses)
    "384712": ("Luxottica Tristar / Ray-Ban Meta Glasses", "SMART_GLASSES", 80),
    "80aa1c": ("Luxottica Tristar / Ray-Ban Meta", "SMART_GLASSES", 80),
    "985949": ("Luxottica Group S.P.A. (Smart Eyewear)", "SMART_GLASSES", 75),

    # Meta Platforms / Facebook Technologies (Wearables / Quest / Smart Eyewear)
    "c0dd8a": ("Meta Platforms Technologies (Wearables/Quest)", "SMART_WEARABLE", 65),
    "4857dd": ("Meta Platforms Technologies", "SMART_WEARABLE", 60),
    "a40e2b": ("Meta Platforms Technologies", "SMART_WEARABLE", 60),
    "78c4fa": ("Meta Platforms Technologies", "SMART_WEARABLE", 60),
    "480560": ("Meta Platforms Technologies", "SMART_WEARABLE", 60),
    "882508": ("Meta Platforms Technologies", "SMART_WEARABLE", 60),
    "94f929": ("Meta Platforms Technologies", "SMART_WEARABLE", 60),
    "b417a8": ("Meta Platforms Technologies", "SMART_WEARABLE", 60),
    "80f3ef": ("Meta Platforms Technologies", "SMART_WEARABLE", 60),
    "8457f7": ("Meta Platforms Technologies", "SMART_WEARABLE", 60),
    "28704e": ("Meta Platforms / Facebook", "SMART_WEARABLE", 60),
    "70ee50": ("Meta Platforms / Facebook", "SMART_WEARABLE", 60),

    # Espressif Systems (ESP8266 / ESP32-CAM - DIY Covert Spy Cameras)
    "18fe34": ("Espressif Inc (ESP32-CAM / IoT)", "IOT_CHIP", 25),
    "240ac4": ("Espressif Inc (ESP32-CAM / IoT)", "IOT_CHIP", 25),
    "2462ab": ("Espressif Inc (ESP32-CAM / IoT)", "IOT_CHIP", 25),
    "246f28": ("Espressif Inc (ESP32-CAM / IoT)", "IOT_CHIP", 25),
    "24b2de": ("Espressif Inc (ESP32-CAM / IoT)", "IOT_CHIP", 25),
    "2c3ae8": ("Espressif Inc (ESP32-CAM / IoT)", "IOT_CHIP", 25),
    "2cf432": ("Espressif Inc (ESP32-CAM / IoT)", "IOT_CHIP", 25),
    "30aea4": ("Espressif Inc (ESP32-CAM / IoT)", "IOT_CHIP", 25),
    "349454": ("Espressif Inc (ESP32-CAM / IoT)", "IOT_CHIP", 25),
    "34987a": ("Espressif Inc (ESP32-CAM / IoT)", "IOT_CHIP", 25),
    "3c6105": ("Espressif Inc (ESP32-CAM / IoT)", "IOT_CHIP", 25),
    "3c71bf": ("Espressif Inc (ESP32-CAM / IoT)", "IOT_CHIP", 25),
    "4022d8": ("Espressif Inc (ESP32-CAM / IoT)", "IOT_CHIP", 25),
    "409151": ("Espressif Inc (ESP32-CAM / IoT)", "IOT_CHIP", 25),
    "483fda": ("Espressif Inc (ESP32-CAM / IoT)", "IOT_CHIP", 25),
    "485519": ("Espressif Inc (ESP32-CAM / IoT)", "IOT_CHIP", 25),
    "4c11ae": ("Espressif Inc (ESP32-CAM / IoT)", "IOT_CHIP", 25),
    "4c7525": ("Espressif Inc (ESP32-CAM / IoT)", "IOT_CHIP", 25),
    "545aa6": ("Espressif Inc (ESP32-CAM / IoT)", "IOT_CHIP", 25),
    "5ccf7f": ("Espressif Inc (ESP32-CAM / IoT)", "IOT_CHIP", 25),
    "600194": ("Espressif Inc (ESP32-CAM / IoT)", "IOT_CHIP", 25),
    "68c63a": ("Espressif Inc (ESP32-CAM / IoT)", "IOT_CHIP", 25),
    "70039f": ("Espressif Inc (ESP32-CAM / IoT)", "IOT_CHIP", 25),
    "7c04d0": ("Espressif Inc (ESP32-CAM / IoT)", "IOT_CHIP", 25),
    "7cdfa1": ("Espressif Inc (ESP32-CAM / IoT)", "IOT_CHIP", 25),
    "807d3a": ("Espressif Inc (ESP32-CAM / IoT)", "IOT_CHIP", 25),
    "840d8e": ("Espressif Inc (ESP32-CAM / IoT)", "IOT_CHIP", 25),
    "84f3eb": ("Espressif Inc (ESP32-CAM / IoT)", "IOT_CHIP", 25),
    "8caab5": ("Espressif Inc (ESP32-CAM / IoT)", "IOT_CHIP", 25),
    "9097d5": ("Espressif Inc (ESP32-CAM / IoT)", "IOT_CHIP", 25),
    "94b555": ("Espressif Inc (ESP32-CAM / IoT)", "IOT_CHIP", 25),
    "94b97e": ("Espressif Inc (ESP32-CAM / IoT)", "IOT_CHIP", 25),
    "98cdac": ("Espressif Inc (ESP32-CAM / IoT)", "IOT_CHIP", 25),
    "a020a6": ("Espressif Inc (ESP32-CAM / IoT)", "IOT_CHIP", 25),
    "a4cf12": ("Espressif Inc (ESP32-CAM / IoT)", "IOT_CHIP", 25),
    "a4e57c": ("Espressif Inc (ESP32-CAM / IoT)", "IOT_CHIP", 25),
    "ac0bfb": ("Espressif Inc (ESP32-CAM / IoT)", "IOT_CHIP", 25),
    "ac67b2": ("Espressif Inc (ESP32-CAM / IoT)", "IOT_CHIP", 25),
    "b4e62d": ("Espressif Inc (ESP32-CAM / IoT)", "IOT_CHIP", 25),
    "bcddc2": ("Espressif Inc (ESP32-CAM / IoT)", "IOT_CHIP", 25),
    "c44f33": ("Espressif Inc (ESP32-CAM / IoT)", "IOT_CHIP", 25),
    "c4dd57": ("Espressif Inc (ESP32-CAM / IoT)", "IOT_CHIP", 25),
    "cc50e3": ("Espressif Inc (ESP32-CAM / IoT)", "IOT_CHIP", 25),
    "d4d4da": ("Espressif Inc (ESP32-CAM / IoT)", "IOT_CHIP", 25),
    "d8a01d": ("Espressif Inc (ESP32-CAM / IoT)", "IOT_CHIP", 25),
    "dc4f22": ("Espressif Inc (ESP32-CAM / IoT)", "IOT_CHIP", 25),
    "dc5475": ("Espressif Inc (ESP32-CAM / IoT)", "IOT_CHIP", 25),
    "e0e2e6": ("Espressif Inc (ESP32-CAM / IoT)", "IOT_CHIP", 25),
    "e831cd": ("Espressif Inc (ESP32-CAM / IoT)", "IOT_CHIP", 25),
    "e86bea": ("Espressif Inc (ESP32-CAM / IoT)", "IOT_CHIP", 25),
    "e89f6d": ("Espressif Inc (ESP32-CAM / IoT)", "IOT_CHIP", 25),
    "ec6260": ("Espressif Inc (ESP32-CAM / IoT)", "IOT_CHIP", 25),
    "ec94cb": ("Espressif Inc (ESP32-CAM / IoT)", "IOT_CHIP", 25),
    "f008d1": ("Espressif Inc (ESP32-CAM / IoT)", "IOT_CHIP", 25),
    "f4cfa2": ("Espressif Inc (ESP32-CAM / IoT)", "IOT_CHIP", 25),

    # Tuya Smart (Hangzhou Tuya Information Technology - Ubiquitous in Cheap Mini Cams)
    "105af7": ("Tuya Smart IoT / Mini Cam", "IOT_CHIP", 25),
    "1869d8": ("Tuya Smart IoT / Mini Cam", "IOT_CHIP", 25),
    "20f41b": ("Tuya Smart IoT / Mini Cam", "IOT_CHIP", 25),
    "381f8d": ("Tuya Smart IoT / Mini Cam", "IOT_CHIP", 25),
    "404cca": ("Tuya Smart IoT / Mini Cam", "IOT_CHIP", 25),
    "48a9d2": ("Tuya Smart IoT / Mini Cam", "IOT_CHIP", 25),
    "508a06": ("Tuya Smart IoT / Mini Cam", "IOT_CHIP", 25),
    "68572d": ("Tuya Smart IoT / Mini Cam", "IOT_CHIP", 25),
    "7089cc": ("Tuya Smart IoT / Mini Cam", "IOT_CHIP", 25),
    "7cf666": ("Tuya Smart IoT / Mini Cam", "IOT_CHIP", 25),
    "84f703": ("Tuya Smart IoT / Mini Cam", "IOT_CHIP", 25),
    "8cce4e": ("Tuya Smart IoT / Mini Cam", "IOT_CHIP", 25),
    "94a9a8": ("Tuya Smart IoT / Mini Cam", "IOT_CHIP", 25),
    "a09208": ("Tuya Smart IoT / Mini Cam", "IOT_CHIP", 25),
    "b88c31": ("Tuya Smart IoT / Mini Cam", "IOT_CHIP", 25),
    "c82b96": ("Tuya Smart IoT / Mini Cam", "IOT_CHIP", 25),
    "dc234d": ("Tuya Smart IoT / Mini Cam", "IOT_CHIP", 25),
    "e09806": ("Tuya Smart IoT / Mini Cam", "IOT_CHIP", 25),
    "e4aaea": ("Tuya Smart IoT / Mini Cam", "IOT_CHIP", 25),
    "f0fe6b": ("Tuya Smart IoT / Mini Cam", "IOT_CHIP", 25),

    # HiSilicon Technologies (Huawei HiSilicon - Security Cam SoCs)
    "001882": ("HiSilicon Technologies (IPC SoC)", "IOT_CHIP", 30),
    "284153": ("HiSilicon Technologies (IPC SoC)", "IOT_CHIP", 30),
    "7054b4": ("HiSilicon Technologies (IPC SoC)", "IOT_CHIP", 30),

    # Allwinner Technology (Embedded Cam SoCs)
    "00e04c": ("Allwinner Technology", "IOT_CHIP", 25),
    "641c67": ("Allwinner Technology", "IOT_CHIP", 25),

    # VStarcam / Eye4
    "000822": ("VStarcam / Eye4 IPCam", "CAM_BRAND", 35),
    "582af7": ("VStarcam / Eye4 IPCam", "CAM_BRAND", 35),
    "4cb16c": ("VStarcam / Eye4 IPCam", "CAM_BRAND", 35),

    # TP-Link (Routers + Tapo/Kasa IP Cams)
    "003192": ("TP-Link (Tapo / Router)", "SMART_DISPLAY", 15),
    "14ebb6": ("TP-Link (Tapo / Router)", "SMART_DISPLAY", 15),
    "1c3bf3": ("TP-Link (Tapo / Router)", "SMART_DISPLAY", 15),
    "20dce6": ("TP-Link (Tapo / Router)", "SMART_DISPLAY", 15),
    "30de4b": ("TP-Link (Tapo / Router)", "SMART_DISPLAY", 15),
    "34e894": ("TP-Link (Tapo / Router)", "SMART_DISPLAY", 15),
    "50c7bf": ("TP-Link (Tapo / Router)", "SMART_DISPLAY", 15),
    "54af97": ("TP-Link (Tapo / Router)", "SMART_DISPLAY", 15),
    "5c628b": ("TP-Link (Tapo / Router)", "SMART_DISPLAY", 15),
    "6032b1": ("TP-Link (Tapo / Router)", "SMART_DISPLAY", 15),
    "6c5ab0": ("TP-Link (Tapo / Router)", "SMART_DISPLAY", 15),
    "704f57": ("TP-Link (Tapo / Router)", "SMART_DISPLAY", 15),
    "7403bd": ("TP-Link (Tapo / Router)", "SMART_DISPLAY", 15),
    "788c54": ("TP-Link (Tapo / Router)", "SMART_DISPLAY", 15),
    "8416f9": ("TP-Link (Tapo / Router)", "SMART_DISPLAY", 15),
    "84d81b": ("TP-Link (Tapo / Router)", "SMART_DISPLAY", 15),
    "909a4a": ("TP-Link (Tapo / Router)", "SMART_DISPLAY", 15),
    "98254a": ("TP-Link (Tapo / Router)", "SMART_DISPLAY", 15),
    "984827": ("TP-Link (Tapo / Router)", "SMART_DISPLAY", 15),
    "a0f3c1": ("TP-Link (Tapo / Router)", "SMART_DISPLAY", 15),
    "ac84c6": ("TP-Link (Tapo / Router)", "SMART_DISPLAY", 15),
    "b09575": ("TP-Link (Tapo / Router)", "SMART_DISPLAY", 15),
    "b4b024": ("TP-Link (Tapo / Router)", "SMART_DISPLAY", 15),
    "c006c3": ("TP-Link (Tapo / Router)", "SMART_DISPLAY", 15),
    "c0c9e3": ("TP-Link (Tapo / Router)", "SMART_DISPLAY", 15),
    "d807b6": ("TP-Link (Tapo / Router)", "SMART_DISPLAY", 15),
    "d84732": ("TP-Link (Tapo / Router)", "SMART_DISPLAY", 15),
    "dcef09": ("TP-Link (Tapo / Router)", "SMART_DISPLAY", 15),
    "e4c32a": ("TP-Link (Tapo / Router)", "SMART_DISPLAY", 15),
    "e848b8": ("TP-Link (Tapo / Router)", "SMART_DISPLAY", 15),
    "f44d5c": ("TP-Link (Tapo / Router)", "SMART_DISPLAY", 15),
    "f4f26d": ("TP-Link (Tapo / Router)", "SMART_DISPLAY", 15),

    # Raspberry Pi (DIY MotionEye Cams)
    "b827eb": ("Raspberry Pi Foundation", "IOT_CHIP", 15),
    "dca632": ("Raspberry Pi Foundation", "IOT_CHIP", 15),
    "e45f01": ("Raspberry Pi Foundation", "IOT_CHIP", 15),
    "28cdc1": ("Raspberry Pi Foundation", "IOT_CHIP", 15),

    # Xiaomi Communications
    "04cf8c": ("Xiaomi Communications", "SMART_DISPLAY", 15),
    "102ab3": ("Xiaomi Communications", "SMART_DISPLAY", 15),
    "14f65a": ("Xiaomi Communications", "SMART_DISPLAY", 15),
    "185936": ("Xiaomi Communications", "SMART_DISPLAY", 15),
    "286c07": ("Xiaomi Communications", "SMART_DISPLAY", 15),
    "34ce00": ("Xiaomi Communications", "SMART_DISPLAY", 15),
    "38a4ed": ("Xiaomi Communications", "SMART_DISPLAY", 15),
    "508f4c": ("Xiaomi Communications", "SMART_DISPLAY", 15),
    "584498": ("Xiaomi Communications", "SMART_DISPLAY", 15),
    "640980": ("Xiaomi Communications", "SMART_DISPLAY", 15),
    "7451ba": ("Xiaomi Communications", "SMART_DISPLAY", 15),
    "7c1dd9": ("Xiaomi Communications", "SMART_DISPLAY", 15),
    "8cbebe": ("Xiaomi Communications", "SMART_DISPLAY", 15),
    "98fae3": ("Xiaomi Communications", "SMART_DISPLAY", 15),
    "a4c361": ("Xiaomi Communications", "SMART_DISPLAY", 15),
    "b0e5ed": ("Xiaomi Communications", "SMART_DISPLAY", 15),
    "c40bcb": ("Xiaomi Communications", "SMART_DISPLAY", 15),
    "d4970b": ("Xiaomi Communications", "SMART_DISPLAY", 15),
    "f01898": ("Xiaomi Communications", "SMART_DISPLAY", 15),
    "f460e2": ("Xiaomi Communications", "SMART_DISPLAY", 15),
    # Consumer & Smart Home Hardware (Phones, TVs, Routers, PCs)
    "e446da": ("Xiaomi Communications", "BENIGN", 0),
    "7c49eb": ("Xiaomi Communications", "BENIGN", 0),
    "640980": ("Xiaomi Communications", "BENIGN", 0),
    "b8ab62": ("Gaoshengda (Smart TV Module)", "BENIGN", 0),
    "d81399": ("Gaoshengda (Smart TV Module)", "BENIGN", 0),
    "702e22": ("Gaoshengda (Smart TV Module)", "BENIGN", 0),
    "e00af6": ("Lite-On Technology (PC/Laptop Wi-Fi)", "BENIGN", 0),
    "f44d5c": ("TP-Link Technologies (Wi-Fi Router)", "BENIGN", 0),
    "50d4f7": ("TP-Link Technologies", "BENIGN", 0),
    "c02567": ("TP-Link Technologies", "BENIGN", 0),
    "3c0630": ("Apple Inc (Mac/iPhone)", "BENIGN", 0),
    "74de2b": ("Samsung Electronics", "BENIGN", 0),
    "ccb0da": ("Samsung Electronics", "BENIGN", 0),
    "28cdc1": ("Roku Inc (Streaming Player)", "BENIGN", 0),
}

# ---------------------------------------------------------------------------
# Suspicious Ports Definitions & Metadata
# ---------------------------------------------------------------------------
PORT_SIGNATURES = {
    554: ("RTSP", "RTSP Video Stream (Universal Camera Feed)", 45),
    8554: ("RTSP-Alt", "RTSP Alternate Streaming Port", 40),
    37777: ("DHIP", "Dahua DVR/NVR/IPCam Control Protocol", 40),
    34567: ("Sofia", "Xiongmai/NETSurveillance Spy Cam Protocol", 45),
    8000: ("Hik-SDK", "Hikvision Web/Device Management Protocol", 30),
    8899: ("ONVIF-WS", "ONVIF Web Services Device Port", 35),
    5000: ("UPnP/Video", "UPnP / Synology Surveillance / ONVIF Alt", 15),
    1935: ("RTMP", "Flash RTMP Video Streaming Protocol", 20),
    7070: ("RealServer", "RealServer RTSP Video Stream", 25),
    7447: ("UniFi-RTSP", "Ubiquiti UniFi Protect RTSP Video Feed", 35),
    10554: ("RTSP-Ext", "RTSP Extended Camera Video Stream", 35),
    9000: ("Cam-Config", "Security Camera Config / Video Server", 20),
    6667: ("Tuya-Control", "Tuya Smart IoT Local Control Protocol", 20),
    6668: ("Tuya-Sec", "Tuya Smart IoT Encrypted Control Protocol", 20),
    80: ("HTTP", "Standard Web Dashboard", 10),
    81: ("HTTP-Cam1", "Common IP Camera Web UI Port", 25),
    82: ("HTTP-Cam2", "Alternate IP Camera Web UI Port", 25),
    83: ("HTTP-Cam3", "Alternate IP Camera Web UI Port", 25),
    84: ("HTTP-Cam4", "Alternate IP Camera Web UI Port", 25),
    88: ("HTTP-Foscam", "Foscam / Generic IP Camera Default Web UI", 30),
    443: ("HTTPS", "HTTPS Secure Web Dashboard", 10),
    8080: ("HTTP-Alt", "HTTP Alternate Web Management", 15),
    8081: ("HTTP-MJPEG", "Common MJPEG Camera Stream Port", 30),
    8082: ("HTTP-Video", "Video Streaming Web Server Port", 25),
    8443: ("HTTPS-Alt", "HTTPS Alternate Web Management", 15),
    8888: ("HTTP-Mgmt", "Embedded Camera Management Port", 20),
    10000: ("Webmin/IoT", "IoT Management Server", 15),
    49152: ("UPnP-Event", "UPnP Base Camera Endpoint", 10),
    49153: ("UPnP-Event2", "UPnP Alternate Camera Endpoint", 10),
    21: ("FTP", "FTP Service (Often used for camera image uploads)", 5),
    22: ("SSH", "SSH Remote Management", 5),
    23: ("Telnet", "Unencrypted Telnet (Common backdoor on cheap cams)", 20),
}

CAMERA_PORTS_QUICK = [80, 81, 88, 443, 554, 8000, 8080, 8081, 8554, 8899, 34567, 37777]
CAMERA_PORTS_FULL = list(PORT_SIGNATURES.keys())

# Camera web server banner signatures
CAMERA_SERVER_HEADERS = [
    "boa", "goahead", "jaws", "hikvision", "dvrdvs", "uc-httpd", "thttpd",
    "mini web server", "web-server/3.0", "ipc server", "hipcam", "foscam",
    "netcam", "yawcam", "axis", "lighttpd"
]

# Camera HTML title and body signatures
CAMERA_HTML_KEYWORDS = [
    "ip camera", "network camera", "ipcam", "live view", "web camera",
    "hikvision", "dahua", "reolink", "foscam", "amcrest", "wyze",
    "netsurveillance", "dvr", "nvr", "snapshot.cgi", "videostream.cgi",
    "mjpeg", "activex", "camera login", "ipcam client", "surveillance system",
    "h.264 dvr", "webcam", "video stream", "camera view", "ocx plugin"
]

# Unauthenticated snapshot URI paths commonly exposed by IP cameras
SNAPSHOT_PATHS = [
    "/snapshot.jpg",
    "/snap.jpg",
    "/cgi-bin/snapshot.cgi",
    "/image.jpg",
    "/onvif/snapshot",
    "/tmpfs/auto.jpg",
    "/jpg/image.jpg",
    "/auto.jpg",
    "/capture",
    "/webcapture.jpg",
    "/ISAPI/Streaming/channels/101/picture",
    "/cgi-bin/viewer/video.jpg",
    "/api/snapshot",
    "/live/snapshot.jpg",
    "/snapshot",
    "/snap",
    "/tmpfs/snap.jpg"
]

# Known default SSID patterns broadcast by covert spy cameras
SPY_CAM_SSID_KEYWORDS = [
    "care-ap", "care_ap", "hd-mini", "hd_mini", "ipcam", "lookcam", "v380",
    "cam-", "cam_", "ipc-", "ipc_", "bgn-", "bgn_", "mv-", "mv_", "tuya",
    "acc-", "acc_", "ai-ball", "hi-cam", "eye-cam", "clock-cam", "clock_cam",
    "pen-cam", "pen_cam", "spy-", "spy_", "wifi-cam", "wifi_cam", "md81s",
    "q7", "a9-", "a9_", "x6-", "x6_", "sq11", "sq13", "sq23", "hd99",
    "hdwificam", "mycam", "vstarcam", "yoosee", "joolink", "icsee", "littlelf",
    "dvr-", "dvr_", "camera", "cctv", "xiaovv", "espcam", "esp32", "live-feed"
]

# Smart glasses and wearable camera Wi-Fi SSID broadcast keywords (P2P / Direct / Sync)
SMART_GLASSES_SSID_KEYWORDS = [
    "ray-ban", "rayban", "meta-view", "meta_view", "meta-glass", "metaglass",
    "stories-", "stories_", "spectacles", "echo-frame", "echo_frame", "vuzix",
    "even-realities", "even_realities", "solos-airgo", "solos_airgo"
]

# Bluetooth SIG assigned Company Identifiers for Smart Glasses & Camera Eyewear
SMART_GLASSES_BLE_SIGNATURES: Dict[int, Tuple[str, str, str, int]] = {
    # Company ID -> (Brand / Manufacturer, Device Model, Description, Base Score Weight)
    0x0D53: (
        "Luxottica Group S.p.A.",
        "Ray-Ban Meta Smart Glasses",
        "Official hardware manufacturer of Ray-Ban Meta & Ray-Ban Stories AI camera glasses. Equipped with 12MP camera & spatial mic array.",
        85
    ),
    0x058E: (
        "Meta Platforms Technologies, LLC",
        "Meta Smart Wearable / AI Glasses",
        "Meta hardware division responsible for smart glasses and spatial wearables.",
        80
    ),
    0x01AB: (
        "Meta Platforms, Inc.",
        "Meta Smart Wearable Device",
        "Meta corporate Bluetooth identity used across companion wearable sensors and smart eyewear.",
        75
    ),
    0x03C2: (
        "Snap Inc.",
        "Snap Spectacles Smart Camera Glasses",
        "Snapchat dual HD stereoscopic camera glasses designed for hands-free video recording.",
        85
    ),
    0x0171: (
        "Amazon.com Services LLC",
        "Amazon Echo Frames (Smart Eyewear)",
        "Alexa-enabled smart frames equipped with directional microphones and voice interface.",
        60
    ),
    0x05D6: (
        "Zhuhai Jieli Technology Co.",
        "AI Smart Glasses / Audio Wearable",
        "Silicon chipset widely deployed across OEM camera and audio smart glasses.",
        70
    ),
    0x08A9: (
        "Even Realities",
        "Even Realities G1 Smart Glasses",
        "Dual micro-LED heads-up display smart glasses with ambient sensors.",
        65
    ),
    0x0A9F: (
        "Brilliant Labs",
        "Brilliant Labs Frame (Multimodal AI Glasses)",
        "Open-source multimodal AI smart glasses with integrated high-resolution camera.",
        80
    ),
    0x0499: (
        "Vuzix Corporation",
        "Vuzix Smart Glasses / AR Eyewear",
        "Enterprise and consumer AR glasses equipped with built-in camera and sensors.",
        75
    ),
    0x0602: (
        "Solos Technology Limited",
        "Solos AirGo Smart Glasses",
        "Smart audio & AI eyewear with voice intelligence and camera integration.",
        65
    )
}

# Local Bluetooth advertising name keywords for smart glasses
SMART_GLASSES_NAME_KEYWORDS = [
    "ray-ban", "rayban", "meta view", "metaview", "meta glass", "stories",
    "spectacles", "echo frames", "vuzix", "even realities", "brilliant frame",
    "solos airgo", "rokid", "xreal", "audio frames", "camera glass"
]

# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------
@dataclass
class Evidence:
    points: int
    category: str  # 'STREAM', 'PROTOCOL', 'VENDOR', 'WEB', 'UPNP', 'MDNS', 'PORT', 'SNAPSHOT', 'AIR_SSID', 'BLE_SIG', 'BLE_NAME'
    description: str
    details: str = ""

@dataclass
class WearableDevice:
    name: str = ""
    address: str = "Unknown"
    device_type: str = "Smart Glasses / AI Eyewear"
    brand: str = "Luxottica / Meta"
    signal: str = "N/A"
    proximity: str = "Unknown"
    company_id: str = ""
    protocol: str = "BLE Advertisement"
    risk_level: str = "CRITICAL"
    score: int = 85
    evidence: List[Evidence] = field(default_factory=list)
    recommendation: str = ""

@dataclass
class RogueAP:
    ssid: str
    bssid: str = "Unknown"
    signal: str = "0%"
    security: str = "Unknown"
    channel: str = ""
    vendor: str = "Unknown"
    vendor_category: str = "BENIGN"
    risk_level: str = "SAFE"  # 'CRITICAL', 'HIGH', 'MEDIUM', 'SAFE'
    score: int = 0
    evidence: List[Evidence] = field(default_factory=list)
    recommendation: str = ""

@dataclass
class DeviceReport:
    ip: str
    mac: str = "Unknown"
    vendor: str = "Unknown"
    vendor_category: str = "BENIGN"
    hostname: str = ""
    device_type: str = "Connected Device"
    is_gateway: bool = False
    is_local: bool = False
    open_ports: List[int] = field(default_factory=list)
    port_banners: Dict[int, str] = field(default_factory=dict)
    services: Dict[str, Any] = field(default_factory=dict)
    http_title: str = ""
    http_server: str = ""
    http_auth_realm: str = ""
    http_urls: List[str] = field(default_factory=list)
    rtsp_active: bool = False
    rtsp_server: str = ""
    onvif_active: bool = False
    onvif_scopes: List[str] = field(default_factory=list)
    upnp_data: Dict[str, str] = field(default_factory=dict)
    mdns_services: List[str] = field(default_factory=list)
    snapshot_captured: bool = False
    snapshot_url: str = ""
    snapshot_b64: str = ""
    score: int = 0
    risk_level: str = "SAFE"  # 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'SAFE'
    evidence: List[Evidence] = field(default_factory=list)
    recommendation: str = ""

# ---------------------------------------------------------------------------
# MAC & Vendor Helpers
# ---------------------------------------------------------------------------
def normalize_mac(mac: str) -> str:
    """Normalize MAC address string to standard format: 00:11:22:33:44:55."""
    clean = re.sub(r"[^0-9a-fA-F]", "", mac).lower()
    if len(clean) == 12:
        return ":".join(clean[i:i+2] for i in range(0, 12, 2))
    return mac.lower().replace("-", ":")

def is_randomized_mac(mac: str) -> bool:
    """Check if MAC address has IEEE locally administered bit set (randomized)."""
    clean = re.sub(r"[^0-9a-fA-F]", "", mac)
    if len(clean) >= 2:
        first_byte = int(clean[:2], 16)
        return bool(first_byte & 0x02)
    return False

def lookup_vendor(mac: str) -> Tuple[str, str, int]:
    """
    Lookup MAC in OUI database.
    Returns: (vendor_name, category, weight)
    """
    clean = re.sub(r"[^0-9a-fA-F]", "", mac).lower()
    if len(clean) >= 6:
        prefix = clean[:6]
        if prefix in OUI_DATABASE:
            return OUI_DATABASE[prefix]

    # Keyword check if vendor string already exists
    if is_randomized_mac(mac):
        return ("Private Wi-Fi MAC (Smartphone/Tablet)", "RANDOMIZED", 5)

    return ("Unknown Manufacturer", "BENIGN", 0)

# ---------------------------------------------------------------------------
# Cross-Platform Local Subnet & Network Discovery
# ---------------------------------------------------------------------------
def detect_local_network(interface_name: Optional[str] = None, subnet_override: Optional[str] = None) -> Tuple[str, str, str]:
    """
    Detect local IP address, active interface name, and target subnet CIDR.
    Works across Linux, macOS, and Windows.
    """
    if subnet_override:
        # Validate user-provided subnet
        try:
            net = ipaddress.ip_network(subnet_override, strict=False)
            return ("127.0.0.1", str(net), interface_name or "Manual")
        except ValueError as e:
            print(f"{C.RED}[!] Invalid subnet CIDR '{subnet_override}': {e}{C.RESET}")
            sys.exit(1)

    local_ip = "127.0.0.1"
    detected_iface = interface_name or "Default"
    subnet_cidr = "192.168.1.0/24"

    # Method 1: Determine primary routing interface via dummy UDP socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Using Google Public DNS IP as routing target (no packets are sent)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except Exception:
        try:
            # Fallback to local hostname
            local_ip = socket.gethostbyname(socket.gethostname())
        except Exception:
            local_ip = "192.168.1.100"

    # Method 2: Detect Subnet Mask based on OS
    os_type = platform.system().lower()
    netmask = "255.255.255.0"  # default /24

    if "windows" in os_type:
        try:
            cmd = "ipconfig"
            out = subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.DEVNULL)
            current_section = False
            for line in out.splitlines():
                if local_ip in line:
                    current_section = True
                if current_section and "Subnet Mask" in line:
                    parts = line.split(":")
                    if len(parts) > 1:
                        netmask = parts[1].strip()
                        break
                if current_section and not line.strip():
                    break
        except Exception:
            pass
    elif "darwin" in os_type:  # macOS
        try:
            out = subprocess.check_output(["ifconfig"], text=True, stderr=subprocess.DEVNULL)
            for block in out.split("\n\n"):
                if local_ip in block:
                    m = re.search(r"netmask (0x[0-9a-fA-F]+)", block)
                    if m:
                        hex_mask = int(m.group(1), 16)
                        netmask = socket.inet_ntoa(struct.pack(">I", hex_mask))
                    break
        except Exception:
            pass
    else:  # Linux
        try:
            out = subprocess.check_output("ip -o -4 addr show", shell=True, text=True, stderr=subprocess.DEVNULL)
            for line in out.splitlines():
                if local_ip in line:
                    m = re.search(r"inet\s+([0-9.]+)/([0-9]+)", line)
                    if m:
                        cidr = f"{m.group(1)}/{m.group(2)}"
                        net = ipaddress.ip_network(cidr, strict=False)
                        return (local_ip, str(net), detected_iface)
        except Exception:
            pass

    try:
        net = ipaddress.ip_network(f"{local_ip}/{netmask}", strict=False)
        subnet_cidr = str(net)
    except Exception:
        parts = local_ip.split(".")
        subnet_cidr = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"

    return (local_ip, subnet_cidr, detected_iface)

def get_default_gateway() -> Optional[str]:
    """Detect default gateway IP on Windows, Linux, and macOS."""
    os_type = platform.system().lower()
    try:
        if "windows" in os_type:
            out = subprocess.check_output("ipconfig", shell=True, text=True, stderr=subprocess.DEVNULL)
            lines = out.splitlines()
            for i, line in enumerate(lines):
                if "Default Gateway" in line:
                    for candidate in [line] + lines[i+1:i+4]:
                        parts = candidate.split(":")
                        val = parts[-1].strip()
                        ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", val)
                        if ip_match and ip_match.group(0) != "0.0.0.0":
                            return ip_match.group(0)
        elif "darwin" in os_type:
            out = subprocess.check_output(["route", "-n", "get", "default"], text=True, stderr=subprocess.DEVNULL)
            for line in out.splitlines():
                if "gateway:" in line:
                    return line.split(":")[1].strip()
        else:  # Linux
            out = subprocess.check_output("ip route show default", shell=True, text=True, stderr=subprocess.DEVNULL)
            m = re.search(r"default via ([0-9.]+)", out)
            if m:
                return m.group(1)
    except Exception:
        pass
    return None

def win_send_arp(ip: str) -> Optional[str]:
    """
    Native Windows SendARP via iphlpapi.dll.
    Directly queries network layer-2 hardware address without relying on external CLI binaries.
    """
    try:
        import ctypes
        dest_ip = struct.unpack('<I', socket.inet_aton(ip))[0]
        mac_buf = (ctypes.c_byte * 6)()
        mac_len = ctypes.c_ulong(6)
        res = ctypes.windll.iphlpapi.SendARP(dest_ip, 0, ctypes.byref(mac_buf), ctypes.byref(mac_len))
        if res == 0:
            mac_bytes = [f"{b & 0xff:02x}" for b in mac_buf]
            m = ":".join(mac_bytes)
            if m != "00:00:00:00:00:00":
                return m
    except Exception:
        pass
    return None

def parse_arp_cache() -> Dict[str, str]:
    """
    Parse OS ARP cache table across Windows, macOS, and Linux.
    Returns: {ip_address: normalized_mac}
    """
    arp_map = {}
    os_type = platform.system().lower()

    # Strategy 1: Linux /proc/net/arp
    if os_type == "linux" and os.path.exists("/proc/net/arp"):
        try:
            with open("/proc/net/arp", "r") as f:
                lines = f.readlines()[1:]
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 4:
                        ip = parts[0]
                        mac = parts[3]
                        if mac != "00:00:00:00:00:00" and re.match(r"^([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$", mac):
                            arp_map[ip] = normalize_mac(mac)
            if arp_map:
                return arp_map
        except Exception:
            pass

    # Strategy 2: System command 'arp -a'
    try:
        cmd = ["arp", "-a"] if "windows" in os_type else "arp -a -n" if "darwin" in os_type else "arp -n"
        out = subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.DEVNULL)
        for line in out.splitlines():
            # Match IP and MAC pairs
            ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line)
            mac_match = re.search(r"\b(?:[0-9a-fA-F]{1,2}[:-]){5}[0-9a-fA-F]{1,2}\b", line)
            if ip_match and mac_match:
                ip = ip_match.group(0)
                mac = mac_match.group(0)
                # Ignore multicast and broadcast IPs
                if not ip.startswith("224.") and not ip.startswith("239.") and not ip.endswith(".255"):
                    arp_map[ip] = normalize_mac(mac)
    except Exception:
        pass

    # Strategy 3: Linux 'ip neigh'
    if os_type == "linux" and not arp_map:
        try:
            out = subprocess.check_output("ip neigh", shell=True, text=True, stderr=subprocess.DEVNULL)
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 5 and "lladdr" in parts:
                    idx = parts.index("lladdr")
                    ip = parts[0]
                    mac = parts[idx + 1]
                    arp_map[ip] = normalize_mac(mac)
        except Exception:
            pass

    return arp_map

def sweep_subnet_arp_ping(network: ipaddress.IPv4Network, timeout: float = 0.5, threads: int = 64) -> Tuple[List[str], Dict[str, str]]:
    """
    Active subnet sweep to stimulate ARP cache and discover live IPs.
    Concurrently attempts native SendARP (Windows) or TCP/UDP socket sweeps (Linux/macOS).
    Returns: (alive_ips_list, direct_arp_map)
    """
    alive_ips = set()
    direct_arp: Dict[str, str] = {}
    all_hosts = [str(ip) for ip in network.hosts()]
    is_windows = "windows" in platform.system().lower()

    def ping_worker(ip: str):
        # On Windows, try native SendARP directly (instant, accurate hardware MAC discovery!)
        if is_windows:
            mac = win_send_arp(ip)
            if mac:
                alive_ips.add(ip)
                direct_arp[ip] = mac
                return

        # Quick TCP connect sweep across key ports (80, 443, 554, 8080)
        # Even if rejected (RST), host is verified alive and ARP table is populated!
        for test_port in [80, 443, 554, 8080]:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(timeout)
                res = s.connect_ex((ip, test_port))
                s.close()
                if res == 0 or res in (10061, 111):  # 0=open, 10061/111=Connection Refused (HOST ALIVE!)
                    alive_ips.add(ip)
                    return
            except Exception:
                pass

        # UDP probe (sends 1 byte UDP to random port, prompts ICMP Unreachable if alive)
        try:
            u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            u.settimeout(timeout)
            u.sendto(b"\x00", (ip, 33434))
            u.close()
        except Exception:
            pass

    with ThreadPoolExecutor(max_workers=min(threads, 128)) as executor:
        list(executor.map(ping_worker, all_hosts))

    # Give OS a brief moment to update ARP cache
    time.sleep(0.2)
    return (list(alive_ips), direct_arp)

# ---------------------------------------------------------------------------
# Multicast Discovery Probes (UPnP SSDP, WS-Discovery ONVIF, mDNS)
# ---------------------------------------------------------------------------
def discover_upnp_ssdp(timeout: float = 2.0) -> Dict[str, Dict[str, str]]:
    """
    Send SSDP M-SEARCH multicast to discover UPnP devices.
    Returns: {ip: {'server': ..., 'location': ..., 'friendly_name': ..., 'model': ..., 'type': ...}}
    """
    ssdp_results = {}
    ssdp_msg = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        "MAN: \"ssdp:discover\"\r\n"
        "MX: 2\r\n"
        "ST: ssdp:all\r\n"
        "\r\n"
    ).encode("utf-8")

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.settimeout(timeout)
        sock.bind(("", 0))
        sock.sendto(ssdp_msg, ("239.255.255.250", 1900))

        start = time.time()
        while time.time() - start < timeout:
            try:
                data, addr = sock.recvfrom(2048)
                ip = addr[0]
                text = data.decode("utf-8", errors="ignore")
                headers = {}
                for line in text.splitlines():
                    if ":" in line:
                        k, v = line.split(":", 1)
                        headers[k.strip().upper()] = v.strip()

                location = headers.get("LOCATION", "")
                server = headers.get("SERVER", "")
                st = headers.get("ST", "")

                if ip not in ssdp_results:
                    ssdp_results[ip] = {
                        "server": server,
                        "location": location,
                        "st": st,
                        "friendly_name": "",
                        "model": "",
                        "device_type": ""
                    }
            except socket.timeout:
                break
            except Exception:
                break
        sock.close()
    except Exception:
        pass

    # Fetch and parse XML descriptors if location URL present
    for ip, info in ssdp_results.items():
        loc = info.get("location")
        if loc and loc.startswith("http"):
            try:
                ctx = ssl._create_unverified_context()
                req = urllib.request.Request(loc, headers={"User-Agent": "OpticHound/2.0"})
                with urllib.request.urlopen(req, timeout=1.5, context=ctx) as resp:
                    xml_text = resp.read().decode("utf-8", errors="ignore")
                    fn_match = re.search(r"<friendlyName>(.*?)</friendlyName>", xml_text, re.IGNORECASE)
                    md_match = re.search(r"<modelName>(.*?)</modelName>", xml_text, re.IGNORECASE)
                    mf_match = re.search(r"<manufacturer>(.*?)</manufacturer>", xml_text, re.IGNORECASE)
                    dt_match = re.search(r"<deviceType>(.*?)</deviceType>", xml_text, re.IGNORECASE)

                    if fn_match: info["friendly_name"] = fn_match.group(1).strip()
                    if md_match: info["model"] = md_match.group(1).strip()
                    if mf_match: info["manufacturer"] = mf_match.group(1).strip()
                    if dt_match: info["device_type"] = dt_match.group(1).strip()
            except Exception:
                pass

    return ssdp_results

def discover_onvif_ws_discovery(timeout: float = 2.0) -> Dict[str, Dict[str, Any]]:
    """
    Send WS-Discovery probe multicast on 239.255.255.250:3702 to discover ONVIF IP cameras.
    Returns: {ip: {'scopes': [...], 'types': [...], 'xaddrs': [...]}}
    """
    onvif_results = {}
    probe_uuid = f"uuid:84829f00-0b3f-11ed-9f89-{int(time.time()):x}"
    probe_soap = f"""<?xml version="1.0" encoding="utf-8"?>
<Envelope xmlns:dn="http://www.onvif.org/ver10/network/wsdl"
          xmlns="http://www.w3.org/2003/05/soap-envelope"
          xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing">
  <Header>
    <wsa:MessageID>{probe_uuid}</wsa:MessageID>
    <wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>
    <wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action>
  </Header>
  <Body>
    <Probe xmlns="http://schemas.xmlsoap.org/ws/2005/04/discovery">
      <Types>dn:NetworkVideoTransmitter</Types>
    </Probe>
  </Body>
</Envelope>""".encode("utf-8")

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.settimeout(timeout)
        sock.bind(("", 0))
        sock.sendto(probe_soap, ("239.255.255.250", 3702))

        start = time.time()
        while time.time() - start < timeout:
            try:
                data, addr = sock.recvfrom(4096)
                ip = addr[0]
                text = data.decode("utf-8", errors="ignore")
                scopes = re.findall(r"onvif://onvif\.org/[^\s<]+", text, re.IGNORECASE)
                xaddrs = re.findall(r"http://[^\s<]+/onvif/[^\s<]+", text, re.IGNORECASE)

                if ip not in onvif_results:
                    onvif_results[ip] = {
                        "active": True,
                        "scopes": scopes,
                        "xaddrs": xaddrs,
                        "raw_soap": text
                    }
            except socket.timeout:
                break
            except Exception:
                break
        sock.close()
    except Exception:
        pass

    return onvif_results

def discover_mdns_services(timeout: float = 1.5) -> Dict[str, List[str]]:
    """
    Query mDNS for camera-related service advertisements (_rtsp._tcp, _http._tcp, _axis-video._tcp).
    Returns: {ip: [service_names]}
    """
    mdns_devices = {}
    if HAVE_ZEROCONF:
        try:
            from zeroconf import Zeroconf, ServiceBrowser

            class CamListener:
                def add_service(self, zc, type_, name):
                    info = zc.get_service_info(type_, name)
                    if info and info.addresses:
                        for addr in info.addresses:
                            ip = socket.inet_ntoa(addr)
                            mdns_devices.setdefault(ip, []).append(f"{name} ({type_})")

            zc = Zeroconf()
            listener = CamListener()
            services = ["_rtsp._tcp.local.", "_http._tcp.local.", "_axis-video._tcp.local.", "_hap._tcp.local."]
            browser = ServiceBrowser(zc, services, listener)
            time.sleep(timeout)
            zc.close()
            return mdns_devices
        except Exception:
            pass

    # Lightweight pure-Python mDNS fallback query
    try:
        # Standard DNS query for _services._dns-sd._udp.local
        query = b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\t_services\x07_dns-sd\x04_udp\x05local\x00\x00\x0c\x00\x01"
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(query, ("224.0.0.251", 5353))
        start = time.time()
        while time.time() - start < timeout:
            try:
                data, addr = sock.recvfrom(2048)
                ip = addr[0]
                text = data.decode("utf-8", errors="ignore")
                found = []
                for s in ["rtsp", "camera", "axis", "video", "hap", "googlecast"]:
                    if s in text.lower():
                        found.append(f"mDNS: {s}")
                if found:
                    mdns_devices.setdefault(ip, []).extend(found)
            except Exception:
                break
        sock.close()
    except Exception:
        pass

    return mdns_devices

# ---------------------------------------------------------------------------
# Deep Protocol Probers: RTSP, HTTP/HTTPS, Xiongmai, Dahua
# ---------------------------------------------------------------------------
def probe_rtsp(ip: str, port: int, timeout: float = 1.2) -> Tuple[bool, str, Dict[str, str]]:
    """
    Probe RTSP video streaming service on target port.
    Sends standard RFC 2326 OPTIONS request and inspects response headers.
    Returns: (is_rtsp, server_banner, headers_dict)
    """
    rtsp_req = (
        f"OPTIONS rtsp://{ip}:{port}/ RTSP/1.0\r\n"
        "CSeq: 1\r\n"
        "User-Agent: OpticHound/2.0\r\n"
        "\r\n"
    ).encode("utf-8")

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        s.sendall(rtsp_req)
        resp = s.recv(2048).decode("utf-8", errors="ignore")
        s.close()

        if "RTSP/1.0" in resp:
            headers = {}
            for line in resp.splitlines():
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip().lower()] = v.strip()
            server = headers.get("server", "RTSP Server")
            return (True, server, headers)
    except Exception:
        pass
    return (False, "", {})

def probe_http(ip: str, port: int, use_ssl: bool = False, timeout: float = 1.5) -> Dict[str, Any]:
    """
    Probe HTTP or HTTPS web management dashboard.
    Extracts HTML title, Server header, WWW-Authenticate realm, and surveillance keywords.
    """
    protocol = "https" if use_ssl else "http"
    url = f"{protocol}://{ip}:{port}/"
    result = {
        "url": url,
        "is_web": False,
        "title": "",
        "server": "",
        "realm": "",
        "found_keywords": [],
        "status_code": None
    }

    try:
        ctx = ssl._create_unverified_context() if use_ssl else None
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) OpticHound/2.0",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
            }
        )
        kwargs = {"timeout": timeout}
        if use_ssl:
            kwargs["context"] = ctx

        with urllib.request.urlopen(req, **kwargs) as resp:
            result["is_web"] = True
            result["status_code"] = resp.status
            result["server"] = resp.headers.get("Server", "").strip()
            raw_body = resp.read(65536).decode("utf-8", errors="ignore")

            # Extract title
            title_m = re.search(r"<title[^>]*>(.*?)</title>", raw_body, re.IGNORECASE | re.DOTALL)
            if title_m:
                result["title"] = title_m.group(1).strip()

            # Search keywords
            body_lower = raw_body.lower()
            for kw in CAMERA_HTML_KEYWORDS:
                if kw in body_lower or kw in result["title"].lower():
                    result["found_keywords"].append(kw)

    except urllib.error.HTTPError as e:
        # HTTP Error (e.g. 401 Unauthorized - very common on IP cameras!)
        result["is_web"] = True
        result["status_code"] = e.code
        result["server"] = e.headers.get("Server", "").strip()
        auth_hdr = e.headers.get("WWW-Authenticate", "")
        realm_m = re.search(r'realm="([^"]+)"', auth_hdr, re.IGNORECASE)
        if realm_m:
            result["realm"] = realm_m.group(1)
        # Scan error body
        try:
            err_body = e.read(16384).decode("utf-8", errors="ignore")
            title_m = re.search(r"<title[^>]*>(.*?)</title>", err_body, re.IGNORECASE | re.DOTALL)
            if title_m:
                result["title"] = title_m.group(1).strip()
            for kw in CAMERA_HTML_KEYWORDS:
                if kw in err_body.lower() or kw in result["title"].lower():
                    result["found_keywords"].append(kw)
        except Exception:
            pass
    except Exception:
        pass

    return result

def probe_xiongmai(ip: str, port: int = 34567, timeout: float = 1.0) -> bool:
    """Check Xiongmai / Sofia / NETSurveillance CCTV control protocol handshake."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        # Sofia keepalive / probe packet: 0xff, 0x00, 0x00, 0x00...
        s.sendall(b"\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
        resp = s.recv(32)
        s.close()
        return len(resp) >= 4 and resp[0] == 0xff
    except Exception:
        return False

def probe_dahua_dhip(ip: str, port: int = 37777, timeout: float = 1.0) -> bool:
    """Check Dahua DHIP protocol handshake."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        # Dahua DHIP header: 0xa0, 0x00, 0x00, 0x60...
        s.sendall(b"\xa0\x00\x00\x60\x00\x00\x00\x00\x00\x00\x00\x00")
        resp = s.recv(16)
        s.close()
        return len(resp) >= 2 and (resp[0] == 0xa0 or resp[0] == 0xb0)
    except Exception:
        return False

def probe_snapshot(ip: str, port: int, use_ssl: bool = False, timeout: float = 1.5) -> Tuple[bool, str, str, bytes]:
    """
    Attempt to fetch unauthenticated live camera snapshot image.
    Returns: (captured, snapshot_url, b64_data_uri, raw_bytes)
    """
    import base64
    protocol = "https" if use_ssl else "http"
    ctx = ssl._create_unverified_context() if use_ssl else None

    for path in SNAPSHOT_PATHS:
        url = f"{protocol}://{ip}:{port}{path}"
        try:
            req = urllib.request.Request(
                url,
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) OpticHound/2.0",
                    "Accept": "image/jpeg,image/png,image/*,*/*"
                }
            )
            kwargs = {"timeout": timeout}
            if use_ssl:
                kwargs["context"] = ctx

            with urllib.request.urlopen(req, **kwargs) as resp:
                if resp.status == 200:
                    data = resp.read(2097152)  # Max 2MB
                    ctype = resp.headers.get("Content-Type", "").lower()
                    is_jpeg = data.startswith(b"\xff\xd8\xff")
                    is_png = data.startswith(b"\x89PNG")
                    if (is_jpeg or is_png or "image" in ctype) and len(data) >= 1024:
                        mime = "image/jpeg" if is_jpeg else "image/png"
                        b64_str = base64.b64encode(data).decode("ascii")
                        data_uri = f"data:{mime};base64,{b64_str}"
                        return (True, url, data_uri, data)
        except Exception:
            pass

    return (False, "", "", b"")

def scan_air_rogue_aps() -> List[RogueAP]:
    """
    Scan over-the-air nearby Wi-Fi SSIDs and BSSIDs for rogue spy camera APs.
    Works across Windows (netsh wlan), macOS (airport/wdutil), and Linux (nmcli/iwlist).
    """
    aps: List[RogueAP] = []
    os_type = platform.system().lower()

    if "windows" in os_type:
        try:
            cmd = "netsh wlan show networks mode=bssid"
            out = subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.DEVNULL)
            current_ssid = ""
            current_auth = "Unknown"
            for line in out.splitlines():
                line = line.strip()
                if line.startswith("SSID "):
                    parts = line.split(":", 1)
                    if len(parts) > 1:
                        current_ssid = parts[1].strip()
                elif line.startswith("Authentication"):
                    parts = line.split(":", 1)
                    if len(parts) > 1:
                        current_auth = parts[1].strip()
                elif line.startswith("BSSID "):
                    parts = line.split(":", 1)
                    if len(parts) > 1:
                        bssid = parts[1].strip()
                        aps.append(RogueAP(
                            ssid=current_ssid,
                            bssid=normalize_mac(bssid),
                            security=current_auth
                        ))
                elif line.startswith("Signal"):
                    parts = line.split(":", 1)
                    if len(parts) > 1 and aps:
                        aps[-1].signal = parts[1].strip()
                elif line.startswith("Channel"):
                    parts = line.split(":", 1)
                    if len(parts) > 1 and aps:
                        aps[-1].channel = parts[1].strip()
        except Exception:
            pass

    elif "darwin" in os_type:  # macOS
        try:
            airport_bin = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
            if os.path.exists(airport_bin):
                out = subprocess.check_output([airport_bin, "-s"], text=True, stderr=subprocess.DEVNULL)
                lines = out.splitlines()[1:]
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 6:
                        ssid = parts[0]
                        bssid = parts[1]
                        rssi = parts[2]
                        sec = " ".join(parts[6:]) if len(parts) > 6 else "Open"
                        aps.append(RogueAP(
                            ssid=ssid,
                            bssid=normalize_mac(bssid),
                            signal=f"{rssi} dBm",
                            security=sec
                        ))
        except Exception:
            pass

    else:  # Linux
        try:
            out = subprocess.check_output("nmcli -t -f SSID,BSSID,SIGNAL,SECURITY dev wifi", shell=True, text=True, stderr=subprocess.DEVNULL)
            for line in out.splitlines():
                parts = line.split(":")
                if len(parts) >= 4:
                    ssid = parts[0]
                    bssid = ":".join(parts[1:7]) if len(parts) >= 8 else parts[1]
                    sig = parts[-2]
                    sec = parts[-1] or "Open"
                    aps.append(RogueAP(
                        ssid=ssid,
                        bssid=normalize_mac(bssid),
                        signal=f"{sig}%",
                        security=sec
                    ))
        except Exception:
            pass

    # Evaluate each AP
    evaluated_aps = []
    for ap in aps:
        score = 0
        ap.evidence = []
        v_name, v_cat, _ = lookup_vendor(ap.bssid)
        ap.vendor = v_name
        ap.vendor_category = v_cat

        ssid_lower = ap.ssid.lower()
        matched_glasses_kw = None
        for kw in SMART_GLASSES_SSID_KEYWORDS:
            if kw in ssid_lower:
                matched_glasses_kw = kw
                break

        matched_kw = None
        for kw in SPY_CAM_SSID_KEYWORDS:
            if kw in ssid_lower:
                matched_kw = kw
                break

        if matched_glasses_kw:
            score += 50
            ap.evidence.append(Evidence(
                points=50,
                category="AIR_SSID",
                description=f"In-Air Wi-Fi Hotspot matches Smart Glasses / Eyewear: '{matched_glasses_kw}' in '{ap.ssid}'",
                details="Direct P2P or setup Wi-Fi broadcasted by camera smart glasses (Ray-Ban Meta / Spectacles) during sync."
            ))
        elif matched_kw:
            score += 45
            ap.evidence.append(Evidence(
                points=45,
                category="AIR_SSID",
                description=f"In-Air Wi-Fi Hotspot matches spy camera name pattern: '{matched_kw}' in '{ap.ssid}'",
                details="Common factory default SSID for covert mini spy cameras operating in P2P mode."
            ))

        if v_cat in ("SMART_GLASSES", "SMART_WEARABLE"):
            score += 40
            ap.evidence.append(Evidence(
                points=40,
                category="VENDOR",
                description=f"Hotspot BSSID matches Smart Glasses Hardware: {v_name}",
                details="Transmitter MAC prefix belongs to Ray-Ban Meta or smart wearable camera manufacturer."
            ))
        elif v_cat in ("CAM_BRAND", "IOT_CHIP"):
            score += 30
            ap.evidence.append(Evidence(
                points=30,
                category="VENDOR",
                description=f"Hotspot BSSID matches hardware: {v_name}",
                details="Transmitter MAC prefix indicates surveillance/IoT manufacturer."
            ))

        if "open" in ap.security.lower() or "none" in ap.security.lower():
            if matched_glasses_kw or matched_kw or v_cat in ("SMART_GLASSES", "SMART_WEARABLE", "CAM_BRAND", "IOT_CHIP"):
                score += 20
                ap.evidence.append(Evidence(
                    points=20,
                    category="SECURITY",
                    description="Unencrypted Open Wi-Fi Network",
                    details="Anyone within radio range can connect directly to this wireless hotspot."
                ))

        sig_val = 0
        if "%" in ap.signal:
            try: sig_val = int(ap.signal.replace("%", "").strip())
            except Exception: pass
        elif "dBm" in ap.signal:
            try:
                dbm = int(ap.signal.replace("dBm", "").strip())
                sig_val = max(0, min(100, 2 * (dbm + 100)))
            except Exception: pass

        if sig_val >= 70 and score > 0:
            score += 15
            ap.evidence.append(Evidence(
                points=15,
                category="PROXIMITY",
                description=f"Strong Signal Strength ({ap.signal}): Device in close physical proximity!",
                details="Signal levels above 70% typically indicate the transmitter is in the same room or unit."
            ))

        ap.score = min(score, 100)
        if ap.score >= 60:
            ap.risk_level = "CRITICAL"
            if matched_glasses_kw or v_cat in ("SMART_GLASSES", "SMART_WEARABLE"):
                ap.recommendation = "SMART CAMERA GLASSES HOTSPOT DETECTED. Outward video/audio eyewear is actively transmitting nearby."
            else:
                ap.recommendation = "ROGUE IN-AIR SPY CAMERA DETECTED. Device is broadcasting its own hotspot. Search room fixtures (clocks, chargers, smoke detectors) immediately."
        elif ap.score >= 35:
            ap.risk_level = "HIGH"
            ap.recommendation = "SUSPICIOUS WIRELESS HOTSPOT. SSID or BSSID matches covert IoT camera or smart wearable hardware."
        elif ap.score >= 20:
            ap.risk_level = "MEDIUM"
            ap.recommendation = "POTENTIAL IOT BEACON. Monitor signal strength."
        else:
            ap.risk_level = "SAFE"
            ap.recommendation = "Standard ambient Wi-Fi network."

        evaluated_aps.append(ap)

    return sorted(evaluated_aps, key=lambda x: x.score, reverse=True)

# ---------------------------------------------------------------------------
# Bluetooth Low Energy (BLE) Smart Glasses & Wearable Detection
# ---------------------------------------------------------------------------
def evaluate_ble_wearable(addr: str, name: str, rssi: int, company_ids: List[str]) -> Optional[WearableDevice]:
    """
    Evaluate detected Bluetooth Low Energy device against known smart glasses signatures
    including Meta Ray-Ban, Snap Spectacles, Echo Frames, Even Realities, and Brilliant Labs.
    """
    matched_brand = None
    device_type = "Smart Eyewear / Camera Wearable"
    score = 0
    evidence = []
    company_id_str = ""

    # 1. Check Bluetooth SIG Company Identifiers in Manufacturer-Specific Data
    for cid in company_ids:
        try:
            val = int(cid, 16) if isinstance(cid, str) and cid.startswith("0x") else int(cid)
            if val in SMART_GLASSES_BLE_SIGNATURES:
                b_name, d_type, desc, w = SMART_GLASSES_BLE_SIGNATURES[val]
                matched_brand = b_name
                device_type = d_type
                score += w
                company_id_str = f"{cid} ({b_name})"
                evidence.append(Evidence(
                    points=w,
                    category="BLE_SIG",
                    description=f"Bluetooth SIG Manufacturer ID matches: {cid} ({b_name})",
                    details=desc
                ))
                break
        except Exception:
            pass

    # 2. Check Advertised Local Name Keywords
    name_lower = name.lower() if name else ""
    matched_kw = None
    for kw in SMART_GLASSES_NAME_KEYWORDS:
        if kw in name_lower:
            matched_kw = kw
            break

    if matched_kw:
        score += 45
        if not matched_brand:
            matched_brand = name
            device_type = f"Smart Glasses ({name})"
        evidence.append(Evidence(
            points=45,
            category="BLE_NAME",
            description=f"Bluetooth Broadcast Name matches smart eyewear: '{name}' (pattern: '{matched_kw}')",
            details="Device advertises directly as camera-equipped smart glasses / smart frames."
        ))

    # 3. Check MAC OUI against Luxottica and Meta hardware blocks
    norm_mac = normalize_mac(addr).replace(":", "")
    for prefix, (vname, vcat, vweight) in OUI_DATABASE.items():
        if norm_mac.startswith(prefix.lower()):
            if vcat in ("SMART_GLASSES", "SMART_WEARABLE"):
                score += 35
                if not matched_brand:
                    matched_brand = vname
                    device_type = "Smart Eyewear / Camera Wearable"
                evidence.append(Evidence(
                    points=35,
                    category="VENDOR",
                    description=f"Bluetooth MAC OUI matches wearable vendor: {vname}",
                    details="Manufacturer specializes in smart glasses or spatial computing."
                ))
                break

    if score == 0:
        return None

    # 4. Proximity & RSSI Distance Heuristics
    prox_label = "Unknown Proximity"
    if rssi > -60:
        prox_label = "Immediate Proximity (< 1.5m)"
        score += 20
        evidence.append(Evidence(
            points=20,
            category="PROXIMITY",
            description=f"Immediate Physical Proximity (RSSI: {rssi} dBm): Transmitting within 1-2 meters!",
            details="Very strong signal indicates someone is wearing, operating, or holding the device directly next to you."
        ))
    elif rssi >= -75:
        prox_label = "Close Proximity (1.5 - 4m)"
        score += 10
        evidence.append(Evidence(
            points=10,
            category="PROXIMITY",
            description=f"Close Physical Proximity (RSSI: {rssi} dBm): Transmitting in room vicinity.",
            details="Device is actively operating inside the current suite or adjacent space."
        ))
    else:
        prox_label = "Moderate Proximity (> 4m)"

    risk_level = "CRITICAL" if score >= 75 else "HIGH" if score >= 45 else "MEDIUM"
    
    brand_lower = (matched_brand or "").lower()
    if "ray-ban" in brand_lower or "luxottica" in brand_lower:
        rec = "ACTIVE SMART CAMERA GLASSES DETECTED. An active pair of Ray-Ban Meta smart glasses is transmitting nearby. Check for privacy LED indicator on outer frame hinge."
    elif "snap" in brand_lower:
        rec = "SNAP SPECTACLES DETECTED. Wearable dual-camera glasses broadcasting nearby."
    elif "echo" in brand_lower or "amazon" in brand_lower:
        rec = "AMAZON ECHO FRAMES DETECTED. Smart audio glasses with directional microphones nearby."
    else:
        rec = "SMART WEARABLE / AI GLASSES DETECTED. Bluetooth radio signals indicate camera or microphone-equipped eyewear in proximity."

    return WearableDevice(
        name=name or (matched_brand or "Smart Glasses"),
        address=addr,
        device_type=device_type,
        brand=matched_brand or "Smart Eyewear Manufacturer",
        signal=f"{rssi} dBm" if rssi != -100 else "Active",
        proximity=prox_label,
        company_id=company_id_str,
        protocol="BLE Advertisement",
        risk_level=risk_level,
        score=min(score, 100),
        evidence=evidence,
        recommendation=rec
    )

def scan_ble_wearables(timeout_secs: float = 3.0) -> List[WearableDevice]:
    """
    Scan nearby Bluetooth Low Energy (BLE) broadcast advertisements to detect
    smart glasses (Ray-Ban Meta, Snap Spectacles, Echo Frames, etc.) and AI camera eyewear.
    Uses native Windows WinRT APIs on Windows, bluetoothctl on Linux, system_profiler on macOS.
    Zero external packages required.
    """
    wearables: List[WearableDevice] = []
    os_type = platform.system().lower()

    if "windows" in os_type:
        try:
            ps_script = f"""
$ErrorActionPreference = 'SilentlyContinue'
$found = @()
try {{
    [Windows.Devices.Bluetooth.BluetoothAdapter, Windows.Devices.Bluetooth, ContentType = WindowsRuntime] | Out-Null
    $op = [Windows.Devices.Bluetooth.BluetoothAdapter]::GetDefaultAsync()
    $adapter = $null
    $t = 0
    while ($op.Status -eq 'Started' -and $t -lt 15) {{ Start-Sleep -Milliseconds 100; $t++ }}
    if ($op.Status -eq 'Completed') {{ $adapter = $op.GetResults() }}
    
    if ($adapter -and $adapter.IsLowEnergySupported) {{
        [Windows.Devices.Bluetooth.Advertisement.BluetoothLEAdvertisementWatcher, Windows.Devices.Bluetooth, ContentType = WindowsRuntime] | Out-Null
        $w = New-Object Windows.Devices.Bluetooth.Advertisement.BluetoothLEAdvertisementWatcher
        $w.ScanningMode = [Windows.Devices.Bluetooth.Advertisement.BluetoothLEScanningMode]::Active
        $map = [System.Collections.Concurrent.ConcurrentDictionary[string, PSObject]]::new()
        
        $handler = [Windows.Foundation.TypedEventHandler[Windows.Devices.Bluetooth.Advertisement.BluetoothLEAdvertisementWatcher, Windows.Devices.Bluetooth.Advertisement.BluetoothLEAdvertisementReceivedEventArgs]]{{
            param($s, $e)
            $cids = @()
            foreach ($m in $e.Advertisement.ManufacturerData) {{
                $cids += ('0x{0:X4}' -f $m.CompanyId)
            }}
            $hex = ('{0:X12}' -f $e.BluetoothAddress) -replace '..(?!$)', '$&:'
            $map[$hex] = [PSCustomObject]@{{
                Address = $hex
                Name = $e.Advertisement.LocalName
                RSSI = $e.RawSignalStrengthInDBm
                CompanyIds = $cids
            }}
        }}
        $token = $w.add_Received($handler)
        $w.Start()
        Start-Sleep -Seconds {int(timeout_secs)}
        $w.Stop()
        $w.remove_Received($token)
        $found = @($map.Values)
    }}
}} catch {{}}
ConvertTo-Json @($found) -Compress
"""
            res = subprocess.run(
                ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_script],
                capture_output=True,
                text=True,
                timeout=timeout_secs + 6
            )
            raw = res.stdout.strip()
            if raw and (raw.startswith("[") or raw.startswith("{")):
                parsed = json.loads(raw)
                items = parsed if isinstance(parsed, list) else [parsed]
                for item in items:
                    addr = item.get("Address", "Unknown")
                    name = item.get("Name", "") or ""
                    rssi = item.get("RSSI", -100)
                    cids = item.get("CompanyIds", [])
                    if isinstance(cids, str):
                        cids = [cids]

                    evaluated = evaluate_ble_wearable(addr, name, rssi, cids)
                    if evaluated:
                        wearables.append(evaluated)
        except Exception:
            pass

    elif "linux" in os_type:
        try:
            cmd = f"timeout {int(timeout_secs)} bluetoothctl --timeout {int(timeout_secs)} scan on"
            subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            out = subprocess.check_output("bluetoothctl devices", shell=True, text=True, stderr=subprocess.DEVNULL)
            for line in out.splitlines():
                parts = line.strip().split(maxsplit=2)
                if len(parts) >= 3 and parts[0] == "Device":
                    addr = parts[1]
                    name = parts[2]
                    evaluated = evaluate_ble_wearable(addr, name, -70, [])
                    if evaluated:
                        wearables.append(evaluated)
        except Exception:
            pass

    elif "darwin" in os_type:  # macOS
        try:
            out = subprocess.check_output(["system_profiler", "SPBluetoothDataType"], text=True, stderr=subprocess.DEVNULL)
            current_device = ""
            for line in out.splitlines():
                line = line.strip()
                if line.endswith(":") and not any(k in line.lower() for k in ["apple", "controller", "hardware", "services", "settings"]):
                    current_device = line[:-1]
                elif "address:" in line.lower() and current_device:
                    addr = line.split(":", 1)[1].strip()
                    evaluated = evaluate_ble_wearable(addr, current_device, -70, [])
                    if evaluated:
                        wearables.append(evaluated)
                    current_device = ""
        except Exception:
            pass

    # Sort wearables by score (descending)
    return sorted(wearables, key=lambda x: x.score, reverse=True)

# ---------------------------------------------------------------------------
# Risk Scoring & Assessment Engine
# ---------------------------------------------------------------------------
def evaluate_device_risk(dev: DeviceReport) -> DeviceReport:
    """
    Compute cumulative risk score (0 - 100), assign risk tier,
    and build human-readable evidence justifications.
    """
    score = 0
    dev.evidence = []

    # 0. Live Unauthenticated Camera Snapshot Captured (+50)
    if dev.snapshot_captured:
        score += 50
        dev.evidence.append(Evidence(
            points=50,
            category="SNAPSHOT",
            description=f"CAPTURED LIVE CAMERA SNAPSHOT from unauthenticated endpoint: {dev.snapshot_url}",
            details="Live optical feed verified! Camera image grabbed directly without credentials."
        ))

    # 1. Verified RTSP Video Streaming (+45)
    if dev.rtsp_active:
        score += 45
        server_str = f" ({dev.rtsp_server})" if dev.rtsp_server else ""
        dev.evidence.append(Evidence(
            points=45,
            category="STREAM",
            description=f"Active RTSP Video Streaming Protocol on port 554/8554{server_str}",
            details="RTSP is almost exclusively used by cameras and surveillance encoders for live video."
        ))
    elif 554 in dev.open_ports or 8554 in dev.open_ports or 7447 in dev.open_ports:
        score += 20
        p = 554 if 554 in dev.open_ports else 8554 if 8554 in dev.open_ports else 7447
        dev.evidence.append(Evidence(
            points=20,
            category="PORT",
            description=f"Open RTSP Video Streaming Port {p}",
            details="Port is open and receptive to network connections."
        ))

    # 2. ONVIF Services (+45)
    if dev.onvif_active:
        score += 45
        dev.evidence.append(Evidence(
            points=45,
            category="PROTOCOL",
            description="Responded to ONVIF WS-Discovery Probe (NetworkVideoTransmitter)",
            details="ONVIF is the international industry standard protocol for IP security cameras."
        ))
    elif 8899 in dev.open_ports:
        score += 15
        dev.evidence.append(Evidence(
            points=15,
            category="PORT",
            description="Port 8899 Open (Standard ONVIF Web Services)",
            details="Commonly exposed by generic white-label IP cameras for remote control."
        ))

    # 3. Dedicated Surveillance Camera Brand (+35)
    if dev.vendor_category == "CAM_BRAND":
        score += 35
        dev.evidence.append(Evidence(
            points=35,
            category="VENDOR",
            description=f"MAC OUI matched security camera brand: {dev.vendor}",
            details="Hardware manufacturer produces dedicated surveillance cameras and security gear."
        ))
    elif dev.vendor_category == "SMART_GLASSES":
        score += 45
        dev.evidence.append(Evidence(
            points=45,
            category="VENDOR",
            description=f"Smart Glasses Hardware Vendor: {dev.vendor}",
            details="Hardware MAC prefix belongs to Ray-Ban Meta or smart wearable eyewear equipped with video camera and microphones."
        ))
    elif dev.vendor_category == "SMART_WEARABLE":
        score += 35
        dev.evidence.append(Evidence(
            points=35,
            category="VENDOR",
            description=f"Smart Wearable Hardware: {dev.vendor}",
            details="Meta hardware platform for smart glasses and spatial computing."
        ))
    elif dev.vendor_category == "IOT_CHIP":
        # Covert spy cams commonly use Espressif or Tuya modules
        score += 25
        dev.evidence.append(Evidence(
            points=25,
            category="VENDOR",
            description=f"MAC OUI matched IoT/Spy Cam Chipset: {dev.vendor}",
            details="Heavily used in miniature spy cameras, hidden clock cameras, and DIY video transmitters."
        ))
    elif dev.vendor_category == "SMART_DISPLAY":
        score += 15
        dev.evidence.append(Evidence(
            points=15,
            category="VENDOR",
            description=f"Smart Home Device with potential camera/mic: {dev.vendor}",
            details="Device may have integrated optical sensors, cameras, or microphones."
        ))

    # 4. Xiongmai / Dahua Proprietary Surveillance Protocols (+40)
    if 34567 in dev.open_ports:
        score += 40
        dev.evidence.append(Evidence(
            points=40,
            category="PROTOCOL",
            description="Port 34567 Open (Xiongmai / NETSurveillance DVR & Spy Cam Protocol)",
            details="Default command and video stream port for hundreds of cheap unbranded Chinese spy cameras."
        ))
    if 37777 in dev.open_ports:
        score += 40
        dev.evidence.append(Evidence(
            points=40,
            category="PROTOCOL",
            description="Port 37777 Open (Dahua DHIP Surveillance Control Protocol)",
            details="Proprietary control and video stream channel used across Dahua security equipment."
        ))
    if 8000 in dev.open_ports and (dev.vendor_category == "CAM_BRAND" or "hikvision" in dev.vendor.lower()):
        score += 30
        dev.evidence.append(Evidence(
            points=30,
            category="PROTOCOL",
            description="Port 8000 Open (Hikvision Video SDK & Control Service)",
            details="Proprietary media communication port on Hikvision cameras and NVRs."
        ))

    # 5. Web Dashboard Signs (Title, Server Header, Keywords, Realm)
    web_signs = 0
    if dev.http_title:
        title_lower = dev.http_title.lower()
        if any(w in title_lower for w in ["camera", "ipcam", "hikvision", "dahua", "reolink", "foscam", "live view", "netsurveillance"]):
            web_signs += 35
            dev.evidence.append(Evidence(
                points=35,
                category="WEB",
                description=f"Web Dashboard Title matches camera: '{dev.http_title}'",
                details="Web management page explicitly identifies itself as a surveillance camera interface."
            ))
        elif any(w in title_lower for w in ["dvr", "nvr", "video", "surveillance"]):
            web_signs += 25
            dev.evidence.append(Evidence(
                points=25,
                category="WEB",
                description=f"Web Dashboard Title suggests video recorder: '{dev.http_title}'",
                details="Interface identifies as a network video recorder or video system."
            ))

    if dev.http_server:
        srv_lower = dev.http_server.lower()
        if any(h in srv_lower for h in CAMERA_SERVER_HEADERS):
            web_signs += 25
            dev.evidence.append(Evidence(
                points=25,
                category="WEB",
                description=f"Embedded Camera Web Server header detected: '{dev.http_server}'",
                details="Embedded web servers like Boa, GoAhead, and JAWS are classic hallmarks of IP camera firmware."
            ))

    if dev.http_auth_realm:
        realm_lower = dev.http_auth_realm.lower()
        if any(r in realm_lower for r in ["camera", "ipcam", "netsurveillance", "hikvision", "dahua", "foscam", "axis"]):
            web_signs += 30
            dev.evidence.append(Evidence(
                points=30,
                category="WEB",
                description=f"Authentication Realm specifies camera: '{dev.http_auth_realm}'",
                details="HTTP 401 challenge realm directly identifies the camera device or model."
            ))

    score += web_signs

    # 6. UPnP / SSDP Descriptor Findings (+20 to +40)
    if dev.upnp_data:
        upnp_str = json.dumps(dev.upnp_data).lower()
        if "camera" in upnp_str or "digitalsecuritycamera" in upnp_str:
            score += 35
            fn = dev.upnp_data.get("friendly_name") or dev.upnp_data.get("model") or "Camera"
            dev.evidence.append(Evidence(
                points=35,
                category="UPNP",
                description=f"UPnP Device Descriptor identifies as camera: '{fn}'",
                details=f"Device XML: {dev.upnp_data.get('device_type', '')}"
            ))

    # 7. mDNS Findings (+20)
    if dev.mdns_services:
        mdns_str = " ".join(dev.mdns_services).lower()
        if any(s in mdns_str for s in ["rtsp", "camera", "axis"]):
            score += 25
            dev.evidence.append(Evidence(
                points=25,
                category="MDNS",
                description=f"mDNS / Zeroconf advertised camera service: {dev.mdns_services[0]}",
                details="Broadcast discovery record indicates streaming video capabilities."
            ))

    # 8. Open Streaming / IoT Management Ports
    for port in dev.open_ports:
        if port in [81, 82, 83, 84, 88, 1935, 5000, 7070, 8008, 8009, 8081, 8082, 8443, 8888, 9000, 10000]:
            sig_name, sig_desc, sig_pts = PORT_SIGNATURES.get(port, ("Open Port", "Open Port", 10))
            score += sig_pts
            dev.evidence.append(Evidence(
                points=sig_pts,
                category="PORT",
                description=f"Port {port} Open ({sig_desc})",
                details=f"Service signature: {sig_name}"
            ))

    # 9. Unencrypted Telnet / Open Management Port (+15)
    if 23 in dev.open_ports:
        score += 15
        dev.evidence.append(Evidence(
            points=15,
            category="PORT",
            description="Telnet (Port 23) Open",
            details="Commonly left open on budget IoT hardware and older camera firmware."
        ))

    # Dampening for known benign devices (e.g. gateway router without camera services)
    if dev.is_gateway and not dev.rtsp_active and not dev.onvif_active:
        score = min(score, 25)
    if dev.is_local and not dev.rtsp_active:
        score = min(score, 10)

    # Cap at 100
    score = min(max(score, 0), 100)
    dev.score = score

    # Classify Risk Level
    if dev.vendor_category == "SMART_GLASSES":
        dev.risk_level = "CRITICAL" if score >= 75 else "HIGH"
        dev.recommendation = "SMART EYEWEAR DETECTED. Ray-Ban Meta or smart camera glasses identified on network. Device features outward-facing video camera and microphone array."
    elif dev.vendor_category == "SMART_WEARABLE":
        dev.risk_level = "HIGH" if score >= 50 else "MEDIUM"
        dev.recommendation = "SMART WEARABLE DETECTED. Meta spatial wearable / AI glasses platform identified."
    elif score >= 75:
        dev.risk_level = "CRITICAL"
        dev.recommendation = "CONFIRMED SURVEILLANCE DEVICE. Immediate physical inspection recommended. Locate lens and report to booking platform if undeclared."
    elif score >= 50:
        dev.risk_level = "HIGH"
        dev.recommendation = "HIGHLY SUSPICIOUS. Strong camera indicators detected. Inspect room fixtures, alarm clocks, smoke detectors, and USB chargers."
    elif score >= 25:
        dev.risk_level = "MEDIUM"
        dev.recommendation = "POTENTIAL SURVEILLANCE / SMART IOT. Device has network services or chipset commonly found in smart home or mini spy devices."
    elif score >= 10:
        dev.risk_level = "LOW"
        dev.recommendation = "UNLIKELY CAMERA. Standard network device or computer with open web/management ports."
    else:
        dev.risk_level = "SAFE"
        dev.recommendation = "BENIGN DEVICE. Appears to be standard authorized network equipment, computer, or phone."

    return dev

# ---------------------------------------------------------------------------
# Device Port Scanner & Worker
# ---------------------------------------------------------------------------
def scan_device(ip: str, mac: str, config: "ScanConfig", upnp_cache: Dict, onvif_cache: Dict, mdns_cache: Dict) -> DeviceReport:
    """
    Perform deep port scanning and service fingerprinting on an identified IP.
    """
    dev = DeviceReport(ip=ip, mac=mac)
    dev.is_gateway = (ip == config.gateway_ip)
    dev.is_local = (ip == config.local_ip)

    # Resolve Hostname
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        dev.hostname = host
    except Exception:
        dev.hostname = ""

    # Lookup OUI Vendor
    v_name, v_cat, _ = lookup_vendor(mac)
    dev.vendor = v_name
    dev.vendor_category = v_cat

    # Check Multicast Caches
    if ip in upnp_cache:
        dev.upnp_data = upnp_cache[ip]
        if dev.upnp_data.get("friendly_name") and not dev.hostname:
            dev.hostname = dev.upnp_data["friendly_name"]
    if ip in onvif_cache:
        dev.onvif_active = True
        dev.onvif_scopes = onvif_cache[ip].get("scopes", [])
    if ip in mdns_cache:
        dev.mdns_services = mdns_cache[ip]

    # Port Scanning
    ports_to_scan = CAMERA_PORTS_QUICK if config.quick_mode else CAMERA_PORTS_FULL
    if config.custom_ports:
        ports_to_scan = config.custom_ports

    open_ports = []
    timeout = config.timeout

    def check_port(port: int):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            res = s.connect_ex((ip, port))
            s.close()
            if res == 0:
                open_ports.append(port)
        except Exception:
            pass

    with ThreadPoolExecutor(max_workers=min(len(ports_to_scan), 32)) as executor:
        list(executor.map(check_port, ports_to_scan))

    dev.open_ports = sorted(open_ports)

    # Deep Probing on Open Ports
    for port in dev.open_ports:
        # RTSP Probing
        if port in [554, 8554, 7447, 10554]:
            is_rtsp, srv, headers = probe_rtsp(ip, port, timeout=config.timeout + 0.5)
            if is_rtsp:
                dev.rtsp_active = True
                dev.rtsp_server = srv
                dev.port_banners[port] = f"RTSP Server: {srv}"

        # HTTP/HTTPS Web Dashboard Probing
        if port in [80, 81, 82, 83, 84, 88, 8080, 8081, 8082, 8888, 9000, 10000]:
            http_res = probe_http(ip, port, use_ssl=False, timeout=config.timeout + 0.5)
            if http_res["is_web"]:
                dev.http_urls.append(http_res["url"])
                if http_res["title"] and not dev.http_title:
                    dev.http_title = http_res["title"]
                if http_res["server"] and not dev.http_server:
                    dev.http_server = http_res["server"]
                if http_res["realm"] and not dev.http_auth_realm:
                    dev.http_auth_realm = http_res["realm"]
                banner_str = f"HTTP {http_res['status_code']} | Server: {http_res['server'] or 'Unknown'}"
                if http_res["title"]:
                    banner_str += f" | Title: '{http_res['title']}'"
                dev.port_banners[port] = banner_str

        if port in [443, 8443]:
            https_res = probe_http(ip, port, use_ssl=True, timeout=config.timeout + 0.5)
            if https_res["is_web"]:
                dev.http_urls.append(https_res["url"])
                if https_res["title"] and not dev.http_title:
                    dev.http_title = https_res["title"]
                if https_res["server"] and not dev.http_server:
                    dev.http_server = https_res["server"]
                if https_res["realm"] and not dev.http_auth_realm:
                    dev.http_auth_realm = https_res["realm"]
                banner_str = f"HTTPS {https_res['status_code']} | Server: {https_res['server'] or 'Unknown'}"
                if https_res["title"]:
                    banner_str += f" | Title: '{https_res['title']}'"
                dev.port_banners[port] = banner_str

        # Xiongmai Probing (34567)
        if port == 34567:
            if probe_xiongmai(ip, port):
                dev.port_banners[port] = "Sofia/Xiongmai CCTV Protocol Handshake Verified"

        # Dahua Probing (37777)
        if port == 37777:
            if probe_dahua_dhip(ip, port):
                dev.port_banners[port] = "Dahua DHIP Protocol Handshake Verified"

    # Snapshot Audit: Try grabbing an unauthenticated camera frame
    if config.snapshot_audit and dev.open_ports:
        for port in dev.open_ports:
            if port in [80, 81, 82, 83, 84, 88, 8080, 8081, 8082, 8888, 9000, 10000, 443, 8443]:
                use_ssl = (port in [443, 8443])
                captured, snap_url, snap_b64, snap_bytes = probe_snapshot(ip, port, use_ssl=use_ssl, timeout=config.timeout + 0.5)
                if captured:
                    dev.snapshot_captured = True
                    dev.snapshot_url = snap_url
                    dev.snapshot_b64 = snap_b64
                    existing = dev.port_banners.get(port, "")
                    dev.port_banners[port] = (existing + " | [LIVE CAMERA SNAPSHOT CAPTURED]").strip(" |")
                    break

    # Determine human-readable device role/type
    if dev.is_gateway:
        dev.device_type = "Wi-Fi Router / Gateway"
        if not dev.hostname:
            dev.hostname = "Router (Default Gateway)"
    elif dev.is_local:
        dev.device_type = "This Computer / Laptop"
        if not dev.hostname:
            dev.hostname = "This PC / Laptop"
    elif dev.snapshot_captured or dev.rtsp_active or dev.onvif_active:
        dev.device_type = "Surveillance Camera (Live Feed)"
    elif dev.vendor_category == "CAM_BRAND":
        dev.device_type = "Security Camera Brand"
    elif dev.vendor_category == "IOT_CHIP":
        dev.device_type = "IoT Controller / Chipset"
    elif dev.vendor_category == "RANDOMIZED":
        dev.device_type = "Smartphone / Tablet (Private MAC)"
        if not dev.hostname:
            dev.hostname = "Guest Smartphone / Tablet"
    elif dev.vendor_category == "SMART_DISPLAY":
        dev.device_type = "Smart Display / Assistant"
    elif dev.vendor_category == "SMART_GLASSES":
        dev.device_type = "Smart Glasses (Ray-Ban Meta / Luxottica)"
        if not dev.hostname:
            dev.hostname = "Ray-Ban Meta Eyewear"
    elif dev.vendor_category == "SMART_WEARABLE":
        dev.device_type = "Meta Smart Wearable / Glasses"
        if not dev.hostname:
            dev.hostname = "Meta Wearable Device"
    elif "Gaoshengda" in dev.vendor or "Roku" in dev.vendor or "TV" in dev.vendor:
        dev.device_type = "Smart TV / Streaming Device"
        if not dev.hostname:
            dev.hostname = "Smart TV / Media Player"
    elif "Xiaomi" in dev.vendor:
        dev.device_type = "Xiaomi Device / Phone"
        if not dev.hostname:
            dev.hostname = "Xiaomi Smart Device"
    elif "Apple" in dev.vendor:
        dev.device_type = "Apple Device"
        if not dev.hostname:
            dev.hostname = "Apple Client"
    elif "Samsung" in dev.vendor:
        dev.device_type = "Samsung Device"
        if not dev.hostname:
            dev.hostname = "Samsung Client"
    elif "TP-Link" in dev.vendor:
        dev.device_type = "TP-Link Network Device"
    elif "Printer" in dev.vendor or "HP" in dev.vendor or "Canon" in dev.vendor or "Epson" in dev.vendor:
        dev.device_type = "Network Printer"
    elif dev.http_title:
        dev.device_type = f"Web Host ('{dev.http_title[:20]}')"
    else:
        dev.device_type = "Connected Network Client"

    # Evaluate Risk Score
    return evaluate_device_risk(dev)

# ---------------------------------------------------------------------------
# Scan Configuration Object
# ---------------------------------------------------------------------------
@dataclass
class ScanConfig:
    local_ip: str = "127.0.0.1"
    gateway_ip: Optional[str] = None
    subnet_cidr: str = "192.168.1.0/24"
    interface_name: str = "Default"
    quick_mode: bool = False
    deep_mode: bool = False
    timeout: float = 1.0
    threads: int = 64
    custom_ports: Optional[List[int]] = None
    air_scan: bool = True
    ble_scan: bool = True
    snapshot_audit: bool = True
    output_html: Optional[str] = None
    no_html: bool = False
    output_json: Optional[str] = None
    mock_mode: bool = False

# ---------------------------------------------------------------------------
# Terminal Reporting
# ---------------------------------------------------------------------------
def safe_print(text: str):
    """Safely print text handling legacy Windows encoding limitations."""
    try:
        print(text)
    except UnicodeEncodeError:
        # Fallback to ASCII representation
        print(text.encode("ascii", errors="replace").decode("ascii"))

def print_banner():
    try:
        art = r"""+------------------------------------------------------------------------------+
|   ___        _   _      _   _                       _                        |
|  / _ \ _ __ | |_(_) ___| | | | ___  _   _ _ __   __| |                       |
| | | | | '_ \| __| |/ __| |_| |/ _ \| | | | '_ \ / _` |                       |
| | |_| | |_) | |_| | (__|  _  | (_) | |_| | | | | (_| |                       |
|  \___/| .__/ \__|_|\___|_| |_|\___/ \__,_|_| |_|\__,_|                       |
|       |_|                                                                    |
|      Rental Stay Hidden Camera & Surveillance Device Detector - v2.0         |
+------------------------------------------------------------------------------+"""
        safe_print(f"\n{C.CYAN}{C.BOLD}{art}{C.RESET}")
    except Exception:
        safe_print("\n[+] OpticHound v2.0 - Hidden Camera & Surveillance Detector\n")

def print_terminal_report(results: List[DeviceReport], config: ScanConfig, duration: float, rogue_aps: Optional[List[RogueAP]] = None, wearables: Optional[List[WearableDevice]] = None):
    """
    Render beautiful, color-coded terminal report with alerts and device cards.
    """
    critical_count = sum(1 for d in results if d.risk_level == "CRITICAL")
    high_count = sum(1 for d in results if d.risk_level == "HIGH")
    medium_count = sum(1 for d in results if d.risk_level == "MEDIUM")
    low_safe_count = len(results) - (critical_count + high_count + medium_count)
    wearable_count = len(wearables) if wearables else 0

    div = "=" * 78
    sub_div = "-" * 78

    safe_print(f"\n{C.BOLD}{div}{C.RESET}")
    safe_print(f"{C.BOLD} SCAN SUMMARY DASHBOARD{C.RESET}  (Completed in {duration:.1f}s across {config.subnet_cidr})")
    safe_print(f"{C.BOLD}{div}{C.RESET}")

    stat_line = f" Total Devices: {C.BOLD}{len(results)}{C.RESET} | "
    if wearable_count > 0:
        stat_line += f"{C.BG_RED} Smart Glasses: {wearable_count} {C.RESET} | "
    if critical_count > 0:
        stat_line += f"{C.BG_RED} CRITICAL: {critical_count} {C.RESET} | "
    else:
        stat_line += f"{C.GREEN}CRITICAL: 0{C.RESET} | "

    if high_count > 0:
        stat_line += f"{C.YELLOW}{C.BOLD}HIGH: {high_count}{C.RESET} | "
    else:
        stat_line += f"{C.GREEN}HIGH: 0{C.RESET} | "

    stat_line += f"{C.BLUE}MEDIUM (IoT): {medium_count}{C.RESET} | {C.DIM}SAFE/LOW: {low_safe_count}{C.RESET}"
    safe_print(stat_line)
    safe_print(f"{C.BOLD}{sub_div}{C.RESET}\n")

    # High / Critical Priority Callouts
    alerts = [d for d in results if d.risk_level in ("CRITICAL", "HIGH")]
    if alerts:
        safe_print(f"{C.BG_RED} [!] HIGH-PRIORITY SURVEILLANCE ALERTS DETECTED {C.RESET}\n")
        for dev in alerts:
            badge_color = C.BG_RED if dev.risk_level == "CRITICAL" else C.BG_YELLOW
            safe_print(f" {badge_color} {dev.risk_level} {C.RESET} {C.BOLD}{dev.ip}{C.RESET} ({dev.mac}) - {C.CYAN}{dev.vendor}{C.RESET}")
            if dev.hostname:
                safe_print(f"     Hostname: {dev.hostname}")
            if dev.http_title:
                safe_print(f"     Web Title: {C.YELLOW}'{dev.http_title}'{C.RESET}")
            if dev.rtsp_active:
                safe_print(f"     RTSP Feed: {C.RED}Active ({dev.rtsp_server or 'Port 554'}){C.RESET}")
            if dev.snapshot_captured:
                safe_print(f"     Snapshot:  {C.BG_RED} [LIVE CAMERA VIEW CAPTURED] {C.RESET} -> {dev.snapshot_url}")
            if dev.open_ports:
                ports_desc = [f"{p} ({PORT_SIGNATURES.get(p, ('Open', ''))[0]})" for p in dev.open_ports]
                safe_print(f"     Open Ports: {', '.join(ports_desc)}")

            safe_print(f"     {C.BOLD}Evidence Log:{C.RESET}")
            for ev in dev.evidence:
                safe_print(f"       * {C.YELLOW}[+{ev.points} pts]{C.RESET} {ev.description}")
            safe_print(f"     {C.BOLD}Action:{C.RESET} {dev.recommendation}\n")

    # Smart Glasses & AI Camera Eyewear Alerts
    if wearables:
        safe_print(f"\n{C.BG_RED} [!] SMART GLASSES & CAMERA EYEWEAR DETECTED IN PROXIMITY {C.RESET}\n")
        safe_print(f" {C.YELLOW}WARNING: Active smart glasses (Meta Ray-Ban / Snap Spectacles) detected nearby!{C.RESET}")
        safe_print(" These wearable devices contain outward-facing cameras and directional audio microphones.\n")
        for w in wearables:
            badge_color = C.BG_RED if w.risk_level == "CRITICAL" else C.BG_YELLOW
            safe_print(f" {badge_color} {w.risk_level} {C.RESET} {C.BOLD}{w.device_type}{C.RESET} ({w.address}) - {C.CYAN}{w.brand}{C.RESET}")
            safe_print(f"     Proximity: {C.YELLOW}{C.BOLD}{w.proximity}{C.RESET} | Signal: {w.signal} | Protocol: {w.protocol}")
            if w.company_id:
                safe_print(f"     Company ID: {w.company_id}")
            safe_print(f"     {C.BOLD}Evidence Log:{C.RESET}")
            for ev in w.evidence:
                safe_print(f"       * {C.YELLOW}[+{ev.points} pts]{C.RESET} {ev.description}")
            safe_print(f"     {C.BOLD}Action:{C.RESET} {w.recommendation}\n")

    # Over-The-Air Rogue Spy Camera Hotspot Alerts
    if rogue_aps:
        suspicious_aps = [ap for ap in rogue_aps if ap.risk_level in ("CRITICAL", "HIGH")]
        if suspicious_aps:
            safe_print(f"\n{C.BG_RED} [!] OVER-THE-AIR ROGUE SPY CAMERA HOTSPOTS (IN-AIR APs) {C.RESET}\n")
            safe_print(f" {C.YELLOW}WARNING: These hidden cameras broadcast their own direct P2P Wi-Fi network.{C.RESET}")
            safe_print(" They are NOT on the main router, but are physically transmitting inside this room!\n")
            for ap in suspicious_aps:
                badge_color = C.BG_RED if ap.risk_level == "CRITICAL" else C.BG_YELLOW
                safe_print(f" {badge_color} {ap.risk_level} {C.RESET} SSID: {C.BOLD}{ap.ssid}{C.RESET} (BSSID: {ap.bssid}) - {C.CYAN}{ap.vendor}{C.RESET}")
                safe_print(f"     Signal: {C.YELLOW}{ap.signal}{C.RESET} | Security: {ap.security}")
                for ev in ap.evidence:
                    safe_print(f"       * {C.YELLOW}[+{ev.points} pts]{C.RESET} {ev.description}")
                safe_print(f"     {C.BOLD}Action:{C.RESET} {ap.recommendation}\n")

    # Detailed Table of All Devices
    safe_print(f"{C.BOLD}ALL DETECTED NETWORK DEVICES ({len(results)} Active Hosts Discovered):{C.RESET}")
    safe_print(f"{C.DIM}{'IP Address':<18} {'Device Type / Role':<28} {'MAC Address':<18} {'Risk':<12} {'Score':<9} {'Vendor / Manufacturer':<28}{C.RESET}")
    safe_print(f"{C.DIM}{'-'*18} {'-'*28} {'-'*18} {'-'*12} {'-'*9} {'-'*28}{C.RESET}")

    for dev in sorted(results, key=lambda x: x.score, reverse=True):
        if dev.risk_level == "CRITICAL":
            r_color = f"{C.RED}{C.BOLD}"
        elif dev.risk_level == "HIGH":
            r_color = f"{C.YELLOW}{C.BOLD}"
        elif dev.risk_level == "MEDIUM":
            r_color = f"{C.BLUE}"
        elif dev.risk_level == "LOW":
            r_color = f"{C.DIM}"
        else:
            r_color = f"{C.GREEN}"

        raw_risk = dev.risk_level
        risk_pad = " " * max(0, 12 - len(raw_risk))
        risk_cell = f"{r_color}{raw_risk}{C.RESET}{risk_pad}"

        score_str = f"{dev.score}/100"
        score_pad = " " * max(0, 9 - len(score_str))
        score_cell = f"{score_str}{score_pad}"

        vendor_display = dev.vendor[:27]
        ip_label = dev.ip
        if dev.is_gateway:
            ip_label += " (GW)"
        elif dev.is_local:
            ip_label += " (You)"

        dev_type = getattr(dev, "device_type", "Network Device")[:27]
        safe_print(f"{ip_label:<18} {dev_type:<28} {dev.mac:<18} {risk_cell} {score_cell} {vendor_display:<28}")

        # Minimal info details line for every connected device
        extra_details = []
        if dev.hostname and dev.hostname != dev_type:
            extra_details.append(f"Host: '{dev.hostname}'")
        if dev.open_ports:
            ports_summary = ", ".join(str(p) for p in dev.open_ports[:6])
            if len(dev.open_ports) > 6:
                ports_summary += f" (+{len(dev.open_ports)-6} more)"
            extra_details.append(f"Open Ports: [{ports_summary}]")
        if dev.http_title:
            extra_details.append(f"Web: '{dev.http_title[:28]}'")
        if dev.rtsp_active:
            extra_details.append("RTSP Video: Active")
        if dev.onvif_active:
            extra_details.append("ONVIF Camera: Active")
        if extra_details:
            safe_print(f"  {C.DIM}↳ {C.RESET}" + f" {C.DIM}|{C.RESET} ".join(extra_details))

    # Practical Rental Stay Advice
    safe_print(f"\n{C.BOLD}{div}{C.RESET}")
    safe_print(f"{C.CYAN}{C.BOLD} [!] TRAVELER'S PHYSICAL INSPECTION CHECKLIST FOR HIDDEN CAMERAS{C.RESET}")
    safe_print(f"{C.BOLD}{div}{C.RESET}")
    safe_print(""" 1. Bedside Alarm Clocks & Radios: Check the front mesh/glass for small circular lenses.
 2. USB Charger Bricks & Power Outlets: Look for pinhole lenses on plug-in adapters.
 3. Smoke & CO Detectors: Especially fixtures directly mounted above beds or bathrooms.
 4. Smartphone Infrared Camera Check: Turn off all lights, open your smartphone camera
    app, and scan the room for glowing purple/white infrared LEDs (night vision).
 5. Flashlight Reflection Test: Shine your phone flashlight at picture frames, screw
    heads, and mirror borders; lenses reflect bluish-purple or greenish light.
 6. Smart Glasses & Audio Frames: Check for sunglasses or spectacles left on tables
    or charging stands. Look for thick temple arms, front corner camera lenses, and
    recording privacy notification LEDs.
 7. If You Find a Camera: Do NOT touch or unplug it. Photograph the device, document
    the location, leave the premises immediately, and contact Airbnb/police support.""")
    safe_print(f"{C.BOLD}{div}{C.RESET}\n")

# ---------------------------------------------------------------------------
# Interactive Dark-Mode HTML Report Generator
# ---------------------------------------------------------------------------
def generate_html_report(results: List[DeviceReport], config: ScanConfig, duration: float, filepath: str, rogue_aps: Optional[List[RogueAP]] = None, wearables: Optional[List[WearableDevice]] = None):
    """
    Generate a standalone, sleek dark-mode HTML report with expandable cards,
    captured live snapshots, over-the-air rogue hotspots, smart glasses alerts, and physical security advice.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    critical_count = sum(1 for d in results if d.risk_level == "CRITICAL")
    high_count = sum(1 for d in results if d.risk_level == "HIGH")
    medium_count = sum(1 for d in results if d.risk_level == "MEDIUM")
    safe_count = len(results) - (critical_count + high_count + medium_count)
    rtsp_count = sum(1 for d in results if d.rtsp_active)
    web_count = sum(1 for d in results if d.http_urls)
    snapshot_count = sum(1 for d in results if d.snapshot_captured)
    rogue_ap_count = sum(1 for a in rogue_aps if a.risk_level in ("CRITICAL", "HIGH")) if rogue_aps else 0
    wearable_count = len(wearables) if wearables else 0

    # Serialize wearables to JSON
    wearables_data = []
    if wearables:
        for w in wearables:
            wearables_data.append({
                "name": w.name,
                "address": w.address,
                "device_type": w.device_type,
                "brand": w.brand,
                "signal": w.signal,
                "proximity": w.proximity,
                "company_id": w.company_id,
                "protocol": w.protocol,
                "risk_level": w.risk_level,
                "score": w.score,
                "evidence": [{"points": e.points, "category": e.category, "description": e.description, "details": e.details} for e in w.evidence],
                "recommendation": w.recommendation
            })

    # Serialize rogue APs to JSON
    rogue_aps_data = []
    if rogue_aps:
        for a in rogue_aps:
            rogue_aps_data.append({
                "ssid": a.ssid,
                "bssid": a.bssid,
                "signal": a.signal,
                "security": a.security,
                "channel": a.channel,
                "vendor": a.vendor,
                "vendor_category": a.vendor_category,
                "risk_level": a.risk_level,
                "score": a.score,
                "evidence": [{"points": e.points, "category": e.category, "description": e.description, "details": e.details} for e in a.evidence],
                "recommendation": a.recommendation
            })

    # Serialize devices to JSON embedded in HTML for client-side search/filter
    devices_data = []
    for d in results:
        devices_data.append({
            "ip": d.ip,
            "mac": d.mac,
            "vendor": d.vendor,
            "vendor_category": d.vendor_category,
            "hostname": d.hostname,
            "device_type": getattr(d, "device_type", "Connected Device"),
            "is_gateway": d.is_gateway,
            "is_local": d.is_local,
            "open_ports": d.open_ports,
            "port_banners": {str(k): v for k, v in d.port_banners.items()},
            "http_title": d.http_title,
            "http_server": d.http_server,
            "http_auth_realm": d.http_auth_realm,
            "http_urls": d.http_urls,
            "rtsp_active": d.rtsp_active,
            "rtsp_server": d.rtsp_server,
            "onvif_active": d.onvif_active,
            "upnp_data": d.upnp_data,
            "mdns_services": d.mdns_services,
            "snapshot_captured": d.snapshot_captured,
            "snapshot_url": d.snapshot_url,
            "snapshot_b64": d.snapshot_b64,
            "score": d.score,
            "risk_level": d.risk_level,
            "evidence": [{"points": e.points, "category": e.category, "description": e.description, "details": e.details} for e in d.evidence],
            "recommendation": d.recommendation
        })

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>OpticHound - Surveillance Audit Report ({timestamp})</title>
<style>
:root {{
  --bg-dark: #0a0e17;
  --card-bg: #111827;
  --card-border: #1f2937;
  --text-primary: #f9fafb;
  --text-secondary: #cbd5e1;
  --text-muted: #94a3b8;
  --cyan-accent: #06b6d4;
  --cyan-glow: rgba(6, 182, 212, 0.15);
  --critical-red: #ef4444;
  --critical-bg: rgba(239, 68, 68, 0.15);
  --high-amber: #f59e0b;
  --high-bg: rgba(245, 158, 11, 0.15);
  --medium-blue: #38bdf8;
  --medium-bg: rgba(56, 189, 248, 0.15);
  --safe-green: #10b981;
  --safe-bg: rgba(16, 185, 129, 0.15);
}}

/* Accessibility & Focus Indicators */
.sr-only {{
  position: absolute;
  width: 1px;
  height: 1px;
  padding: 0;
  margin: -1px;
  overflow: hidden;
  clip: rect(0, 0, 0, 0);
  white-space: nowrap;
  border-width: 0;
}}

button:focus-visible, input:focus-visible, .device-header:focus-visible, a:focus-visible {{
  outline: 2px solid var(--cyan-accent);
  outline-offset: 2px;
}}

.legal-link {{
  background: none;
  border: none;
  color: var(--cyan-accent);
  cursor: pointer;
  font-size: 13px;
  text-decoration: underline;
  padding: 2px 6px;
  border-radius: 4px;
}}
.legal-link:hover {{
  color: #38bdf8;
}}

/* Modal Governance Dialog */
.modal-overlay {{
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: rgba(0, 0, 0, 0.85);
  display: none;
  align-items: center;
  justify-content: center;
  z-index: 9999;
  padding: 16px;
  backdrop-filter: blur(4px);
}}
.modal-overlay.active {{
  display: flex;
}}
.modal-box {{
  background: #0f172a;
  border: 1px solid var(--card-border);
  border-radius: 12px;
  max-width: 780px;
  width: 100%;
  max-height: 85vh;
  display: flex;
  flex-direction: column;
  overflow: hidden;
  box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.8);
}}
.modal-header {{
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 16px 20px;
  border-bottom: 1px solid var(--card-border);
  background: #1e293b;
}}
.modal-header h3 {{
  font-size: 16px;
  font-weight: 700;
  color: #f8fafc;
}}
.modal-close {{
  background: #334155;
  border: none;
  color: #f8fafc;
  font-size: 18px;
  width: 32px;
  height: 32px;
  border-radius: 6px;
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
}}
.modal-close:hover {{
  background: #475569;
}}
.modal-tabs {{
  display: flex;
  gap: 8px;
  padding: 10px 20px;
  background: #111827;
  border-bottom: 1px solid var(--card-border);
  flex-wrap: wrap;
}}
.modal-body {{
  padding: 24px;
  overflow-y: auto;
  font-size: 13px;
  line-height: 1.6;
  color: #cbd5e1;
}}
.modal-body h4 {{
  color: var(--cyan-accent);
  margin: 16px 0 6px 0;
  font-size: 15px;
}}
.modal-body p {{
  margin-bottom: 10px;
}}
.modal-body ul {{
  margin-left: 20px;
  margin-bottom: 12px;
}}
.modal-body li {{
  margin-bottom: 4px;
}}

* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  background-color: var(--bg-dark);
  color: var(--text-primary);
  line-height: 1.5;
  padding: 24px;
}}

.container {{
  max-width: 1200px;
  margin: 0 auto;
}}

/* Header Banner */
.header {{
  display: flex;
  justify-content: space-between;
  align-items: center;
  flex-wrap: wrap;
  gap: 16px;
  padding-bottom: 24px;
  border-bottom: 1px solid var(--card-border);
  margin-bottom: 24px;
}}
.header-title {{
  display: flex;
  align-items: center;
  gap: 12px;
}}
.logo-icon {{
  font-size: 32px;
  background: linear-gradient(135deg, #06b6d4, #3b82f6);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
}}
.title-text h1 {{
  font-size: 24px;
  font-weight: 700;
  letter-spacing: -0.5px;
}}
.title-text p {{
  font-size: 13px;
  color: var(--text-secondary);
}}
.meta-badges {{
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
}}
.meta-badge {{
  background: #1e293b;
  border: 1px solid #334155;
  padding: 6px 12px;
  border-radius: 6px;
  font-size: 12px;
  font-family: monospace;
}}

/* Stat Cards */
.stats-grid {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 16px;
  margin-bottom: 28px;
}}
.stat-card {{
  background: var(--card-bg);
  border: 1px solid var(--card-border);
  border-radius: 10px;
  padding: 16px;
  position: relative;
  overflow: hidden;
}}
.stat-card.critical {{ border-top: 3px solid var(--critical-red); }}
.stat-card.high {{ border-top: 3px solid var(--high-amber); }}
.stat-card.medium {{ border-top: 3px solid var(--medium-blue); }}
.stat-card.safe {{ border-top: 3px solid var(--safe-green); }}
.stat-card.neutral {{ border-top: 3px solid var(--cyan-accent); }}
.stat-val {{
  font-size: 28px;
  font-weight: 800;
  margin-top: 4px;
}}
.stat-label {{
  font-size: 12px;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  color: var(--text-secondary);
}}

/* Controls & Filters */
.controls-bar {{
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 16px;
  flex-wrap: wrap;
  margin-bottom: 20px;
}}
.search-box {{
  flex: 1;
  min-width: 260px;
  position: relative;
}}
.search-box input {{
  width: 100%;
  padding: 10px 16px;
  background: var(--card-bg);
  border: 1px solid var(--card-border);
  border-radius: 8px;
  color: var(--text-primary);
  font-size: 14px;
  outline: none;
}}
.search-box input:focus {{
  border-color: var(--cyan-accent);
}}
.filter-pills {{
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
}}
.pill {{
  background: var(--card-bg);
  border: 1px solid var(--card-border);
  color: var(--text-secondary);
  padding: 8px 14px;
  border-radius: 8px;
  font-size: 13px;
  cursor: pointer;
  transition: all 0.2s;
}}
.pill:hover {{
  color: var(--text-primary);
  border-color: #374151;
}}
.pill.active {{
  background: #1e293b;
  border-color: var(--cyan-accent);
  color: var(--cyan-accent);
  font-weight: 600;
}}

/* Device Card Accordion */
.devices-list {{
  display: flex;
  flex-direction: column;
  gap: 12px;
  margin-bottom: 40px;
}}
.device-card {{
  background: var(--card-bg);
  border: 1px solid var(--card-border);
  border-radius: 10px;
  overflow: hidden;
  transition: border-color 0.2s;
}}
.device-card:hover {{
  border-color: #374151;
}}
.device-header {{
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 16px 20px;
  cursor: pointer;
  user-select: none;
  gap: 16px;
  flex-wrap: wrap;
}}
.device-main {{
  display: flex;
  align-items: center;
  gap: 14px;
  flex: 1;
}}
.status-dot {{
  width: 12px;
  height: 12px;
  border-radius: 50%;
  flex-shrink: 0;
}}
.status-dot.CRITICAL {{ background-color: var(--critical-red); box-shadow: 0 0 10px var(--critical-red); }}
.status-dot.HIGH {{ background-color: var(--high-amber); box-shadow: 0 0 10px var(--high-amber); }}
.status-dot.MEDIUM {{ background-color: var(--medium-blue); }}
.status-dot.LOW, .status-dot.SAFE {{ background-color: var(--safe-green); }}

.device-ids {{
  display: flex;
  flex-direction: column;
}}
.ip-text {{
  font-size: 16px;
  font-weight: 700;
  font-family: monospace;
}}
.hostname-text {{
  font-size: 12px;
  color: var(--text-secondary);
}}
.vendor-tag {{
  font-size: 12px;
  background: #1e293b;
  padding: 3px 8px;
  border-radius: 4px;
  color: #cbd5e1;
  max-width: 250px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}}
.mac-tag {{
  font-size: 12px;
  font-family: monospace;
  color: var(--text-muted);
}}
.risk-badge {{
  padding: 4px 10px;
  border-radius: 6px;
  font-size: 12px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}}
.risk-badge.CRITICAL {{ background: var(--critical-bg); color: var(--critical-red); border: 1px solid rgba(239, 68, 68, 0.3); }}
.risk-badge.HIGH {{ background: var(--high-bg); color: var(--high-amber); border: 1px solid rgba(245, 158, 11, 0.3); }}
.risk-badge.MEDIUM {{ background: var(--medium-bg); color: var(--medium-blue); border: 1px solid rgba(59, 130, 246, 0.3); }}
.risk-badge.LOW, .risk-badge.SAFE {{ background: var(--safe-bg); color: var(--safe-green); border: 1px solid rgba(16, 185, 129, 0.3); }}

.score-indicator {{
  font-size: 14px;
  font-weight: 700;
  font-family: monospace;
  min-width: 60px;
  text-align: right;
}}

/* Expanded Details */
.device-body {{
  padding: 0 20px 20px 20px;
  border-top: 1px solid var(--card-border);
  display: none;
}}
.device-card.open .device-body {{
  display: block;
}}
.recommendation-banner {{
  margin: 16px 0;
  padding: 12px 16px;
  border-radius: 8px;
  font-size: 13px;
  font-weight: 600;
}}
.recommendation-banner.CRITICAL {{ background: var(--critical-bg); color: #fca5a5; border-left: 4px solid var(--critical-red); }}
.recommendation-banner.HIGH {{ background: var(--high-bg); color: #fde68a; border-left: 4px solid var(--high-amber); }}
.recommendation-banner.MEDIUM {{ background: var(--medium-bg); color: #bfdbfe; border-left: 4px solid var(--medium-blue); }}
.recommendation-banner.SAFE, .recommendation-banner.LOW {{ background: var(--safe-bg); color: #a7f3d0; border-left: 4px solid var(--safe-green); }}

.section-title {{
  font-size: 12px;
  font-weight: 700;
  text-transform: uppercase;
  color: var(--text-secondary);
  margin: 16px 0 8px 0;
  letter-spacing: 0.5px;
}}
.evidence-list {{
  display: flex;
  flex-direction: column;
  gap: 6px;
}}
.evidence-item {{
  display: flex;
  align-items: flex-start;
  gap: 10px;
  background: #1e293b;
  padding: 8px 12px;
  border-radius: 6px;
  font-size: 13px;
}}
.points-tag {{
  background: #334155;
  color: #38bdf8;
  font-family: monospace;
  font-size: 11px;
  font-weight: 700;
  padding: 2px 6px;
  border-radius: 4px;
  flex-shrink: 0;
}}

.ports-table {{
  width: 100%;
  border-collapse: collapse;
  font-size: 13px;
  margin-top: 8px;
}}
.ports-table th, .ports-table td {{
  padding: 8px 12px;
  text-align: left;
  border-bottom: 1px solid var(--card-border);
}}
.ports-table th {{
  color: var(--text-secondary);
  font-size: 11px;
  text-transform: uppercase;
}}
.ports-table td.port-cell {{
  font-family: monospace;
  font-weight: 700;
  color: var(--cyan-accent);
}}

/* Security Checklist */
.checklist-card {{
  background: var(--card-bg);
  border: 1px solid var(--card-border);
  border-radius: 10px;
  padding: 24px;
  margin-top: 32px;
}}
.checklist-grid {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: 16px;
  margin-top: 16px;
}}
.checklist-item {{
  background: #1e293b;
  padding: 14px;
  border-radius: 8px;
  font-size: 13px;
}}
.checklist-item h4 {{
  font-size: 14px;
  margin-bottom: 6px;
  color: var(--cyan-accent);
  display: flex;
  align-items: center;
  gap: 8px;
}}

.footer {{
  text-align: center;
  padding: 32px 0 16px 0;
  color: var(--text-muted);
  font-size: 12px;
}}
</style>
</head>
<body>

<div class="container">
  <!-- Header -->
  <div class="header">
    <div class="header-title">
      <div class="logo-icon">👁️</div>
      <div class="title-text">
        <h1>OpticHound Surveillance Audit</h1>
        <p>Wi-Fi Hidden Camera & IoT Risk Intelligence Report</p>
      </div>
    </div>
    <div class="meta-badges">
      <div class="meta-badge">Target: {config.subnet_cidr}</div>
      <div class="meta-badge">Scan Time: {timestamp}</div>
      <div class="meta-badge">Duration: {duration:.1f}s</div>
      <div class="meta-badge" style="color:var(--safe-green); border-color:rgba(16, 185, 129, 0.4);">🛡️ 100% Local • Zero Telemetry</div>
    </div>
  </div>

  <!-- Stat Counters -->
  <div class="stats-grid">
    <div class="stat-card neutral">
      <div class="stat-label">Total Devices</div>
      <div class="stat-val">{len(results)}</div>
    </div>
    <div class="stat-card critical">
      <div class="stat-label">Smart Glasses</div>
      <div class="stat-val" style="color: {'var(--critical-red)' if wearable_count > 0 else 'var(--text-muted)'};">{wearable_count}</div>
    </div>
    <div class="stat-card critical">
      <div class="stat-label">Critical Cams</div>
      <div class="stat-val" style="color: var(--critical-red);">{critical_count}</div>
    </div>
    <div class="stat-card high">
      <div class="stat-label">In-Air Rogue APs</div>
      <div class="stat-val" style="color: var(--high-amber);">{rogue_ap_count}</div>
    </div>
    <div class="stat-card critical">
      <div class="stat-label">Snapshots Captured</div>
      <div class="stat-val" style="color: #38bdf8;">{snapshot_count}</div>
    </div>
    <div class="stat-card medium">
      <div class="stat-label">IoT / Medium</div>
      <div class="stat-val" style="color: var(--medium-blue);">{medium_count}</div>
    </div>
    <div class="stat-card neutral">
      <div class="stat-label">RTSP Streams</div>
      <div class="stat-val">{rtsp_count}</div>
    </div>
  </div>

  <!-- Search & Filter Controls -->
  <div class="controls-bar">
    <div class="search-box">
      <label for="searchInput" class="sr-only">Search devices by IP, MAC, Brand, Port, or Web Title</label>
      <input type="text" id="searchInput" name="search" aria-label="Search devices by IP, MAC, Brand, Port, or Web Title" placeholder="Search by IP, MAC, Brand, Port, or Web Title...">
    </div>
    <div class="filter-pills" role="toolbar" aria-label="Device Risk Filters">
      <button type="button" class="pill active" onclick="setFilter('ALL')" aria-label="Filter: Show all devices">All ({len(results)})</button>
      <button type="button" class="pill" onclick="setFilter('ALERTS')" aria-label="Filter: Show high-priority alerts only">Alerts Only ({critical_count + high_count + wearable_count})</button>
      <button type="button" class="pill" onclick="setFilter('GLASSES')" aria-label="Filter: Show smart glasses and AI eyewear">Eyewear ({wearable_count})</button>
      <button type="button" class="pill" onclick="setFilter('CRITICAL')" aria-label="Filter: Show critical risk cameras">Critical ({critical_count})</button>
      <button type="button" class="pill" onclick="setFilter('HIGH')" aria-label="Filter: Show high risk devices">High ({high_count})</button>
      <button type="button" class="pill" onclick="setFilter('MEDIUM')" aria-label="Filter: Show IoT devices">IoT ({medium_count})</button>
      <button type="button" class="pill" onclick="setFilter('SAFE')" aria-label="Filter: Show safe devices">Safe ({safe_count})</button>
      <button type="button" class="pill" onclick="toggleAllCards()" aria-label="Expand or collapse all device cards">Toggle All</button>
    </div>
  </div>

  <!-- Detected Smart Glasses & Camera Eyewear Section -->
  <div class="checklist-card" id="wearablesContainer" style="display:none; margin-bottom:28px; border-left:4px solid var(--critical-red);">
    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px; flex-wrap:wrap; gap:8px;">
      <div>
        <h3 style="font-size:18px; font-weight:700;">🕶️ Detected Smart Glasses &amp; Camera Eyewear</h3>
        <p style="font-size:13px; color:var(--text-secondary);">Nearby Bluetooth LE or wireless smart glasses (Ray-Ban Meta, Snap Spectacles, AI frames) equipped with video cameras and microphones.</p>
      </div>
      <span class="meta-badge" id="wearablesCountBadge" style="background:#7f1d1d; color:#fca5a5; border-color:#ef4444;">0 Eyewear</span>
    </div>
    <div id="wearablesListContainer" style="display:flex; flex-direction:column; gap:10px;"></div>
  </div>

  <!-- Devices Accordion List -->
  <div class="devices-list" id="devicesContainer" role="region" aria-label="Discovered Devices List">
    <!-- Populated by JavaScript -->
  </div>

  <!-- Over-the-Air Rogue Wi-Fi Hotspots Section -->
  <div class="checklist-card" id="airNetworksContainer" style="display:none; margin-bottom:28px;">
    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px; flex-wrap:wrap; gap:8px;">
      <div>
        <h3 style="font-size:18px; font-weight:700;">📡 Over-the-Air Rogue Wi-Fi Hotspots & In-Air Beacons</h3>
        <p style="font-size:13px; color:var(--text-secondary);">Direct P2P or setup hotspots broadcasting in wireless proximity (even if not connected to the router).</p>
      </div>
      <span class="meta-badge" id="airCountBadge">0 Networks</span>
    </div>
    <div id="airListContainer" style="display:flex; flex-direction:column; gap:10px;"></div>
  </div>

  <!-- Physical Security Checklist for Rental Stays -->
  <div class="checklist-card">
    <h3 style="font-size: 18px; font-weight: 700; margin-bottom: 4px;">🕵️ Traveler's Physical Inspection Guide</h3>
    <p style="font-size: 13px; color: var(--text-secondary);">Even hidden cameras with hidden SSIDs or offline memory cards leave physical clues. Perform these checks in bedrooms and bathrooms.</p>
    
    <div class="checklist-grid">
      <div class="checklist-item">
        <h4>⏰ Bedside Alarm Clocks</h4>
        <p>Modern hidden cameras are often housed inside functional digital alarm clocks facing the bed. Inspect the tinted acrylic face with a direct flashlight beam to spot circular lenses.</p>
      </div>
      <div class="checklist-item">
        <h4>🔌 USB Chargers & Adapters</h4>
        <p>Wall charger cubes plugged into outlets near the bed or bathroom frequently conceal pinhole cameras. Unplug suspect wall adapters and inspect the front face for a pinhole aperture.</p>
      </div>
      <div class="checklist-item">
        <h4>🚨 Smoke & CO Detectors</h4>
        <p>Examine ceiling smoke detectors directly over the bed or shower. Pinhole cameras require an unobstructed hole that often differs from standard alarm vents.</p>
      </div>
      <div class="checklist-item">
        <h4>🔦 Phone Flashlight Reflection</h4>
        <p>Turn off room lights. Shine your smartphone flashlight at wall art, screw heads, AC vents, and mirror frames. Camera lenses will produce a distinctive purple, green, or blue reflection.</p>
      </div>
      <div class="checklist-item">
        <h4>📱 Infrared Night Vision Test</h4>
        <p>Darken the room completely. Open your phone camera (or selfie camera) and look around. Night-vision infrared LEDs emit a glowing violet or bright white dot on camera sensors.</p>
      </div>
      <div class="checklist-item">
        <h4>🕶️ Smart Glasses &amp; Camera Frames</h4>
        <p>Inspect sunglasses or spectacles left on tables, bedside shelves, or charging docks. Look for unusually thick temple arms (housing battery/electronics), front corner pinhole camera lenses adjacent to frame hinges, and white privacy notification LEDs.</p>
      </div>
      <div class="checklist-item">
        <h4>📸 If You Spot a Camera</h4>
        <p>Do NOT tamper with or disconnect the camera. Photograph the device and surrounding room context, leave the rental immediately, and contact Airbnb/booking customer support and local police.</p>
      </div>
    </div>
  </div>

  <div class="footer" role="contentinfo">
    <div style="margin-bottom: 12px; display: flex; justify-content: center; gap: 16px; flex-wrap: wrap; align-items: center;">
      <button type="button" class="legal-link" onclick="openLegalModal('privacy')">Privacy Policy</button>
      <span style="color: var(--text-muted);">•</span>
      <button type="button" class="legal-link" onclick="openLegalModal('terms')">Terms &amp; Conditions</button>
      <span style="color: var(--text-muted);">•</span>
      <button type="button" class="legal-link" onclick="openLegalModal('cookies')">Cookie Statement</button>
      <span style="color: var(--text-muted);">•</span>
      <button type="button" class="legal-link" onclick="openLegalModal('dpdp')">DPDP Act (India)</button>
    </div>
    <p>Generated by OpticHound v2.0 • Offline Security Audit Engine • {timestamp}</p>
    <p style="font-size: 11px; margin-top: 6px; color: var(--text-muted);">
      100% Free &amp; Open-Source • Zero Cookies • No Telemetry • No External CDNs • Intended for authorized audits by users aged 18+
    </p>
  </div>
</div>

<!-- Legal & Privacy Governance Modal Dialog -->
<div id="legalModal" class="modal-overlay" role="dialog" aria-modal="true" aria-labelledby="modalTitle" onclick="if(event.target===this)closeLegalModal()">
  <div class="modal-box">
    <div class="modal-header">
      <h3 id="modalTitle">Legal &amp; Privacy Governance</h3>
      <button type="button" class="modal-close" onclick="closeLegalModal()" aria-label="Close dialog">✕</button>
    </div>
    <div class="modal-tabs">
      <button type="button" class="pill active" id="tab-privacy" onclick="showLegalTab('privacy')">Privacy Policy</button>
      <button type="button" class="pill" id="tab-terms" onclick="showLegalTab('terms')">Terms of Use</button>
      <button type="button" class="pill" id="tab-cookies" onclick="showLegalTab('cookies')">Cookie Policy</button>
      <button type="button" class="pill" id="tab-dpdp" onclick="showLegalTab('dpdp')">DPDP Act (India)</button>
    </div>
    <div class="modal-body" id="modalBody"></div>
  </div>
</div>

<script>
const devices = {json.dumps(devices_data)};
const rogueAPs = {json.dumps(rogue_aps_data)};
const wearables = {json.dumps(wearables_data)};
let currentFilter = 'ALL';
let allExpanded = false;

const legalContent = {{
  privacy: `
    <h4>100% Local &amp; Private Edge Processing</h4>
    <p>OpticHound processes all network data strictly inside your local machine's memory. It contains zero analytics, zero telemetry tracking, zero session-replay tools, and zero cloud uploads. Your audit results never leave your machine.</p>
    <h4>Data Minimization</h4>
    <p>Only standard Layer-2 (ARP/MAC) and Layer-3 (IP/Port) headers are scanned to identify surveillance hardware. No user accounts, credentials, or personal profiles are created or stored.</p>
    <h4>Reports Stored Locally</h4>
    <p>Generated HTML and JSON reports are saved directly on your local storage drive under your full ownership and control.</p>
    <h4>Zero External Requests</h4>
    <p>This report contains zero external fonts, scripts, stylesheets, or remote images. It operates safely in air-gapped or offline environments.</p>
  `,
  terms: `
    <h4>Authorized &amp; Ethical Network Auditing</h4>
    <p>OpticHound is designed exclusively for lawful self-defense, traveler safety, and authorized network auditing. Users must only scan networks they own, administer, or are authorized to inspect (such as rental guests auditing the guest Wi-Fi provided during their paid stay).</p>
    <h4>Prohibited Uses</h4>
    <p>Unauthorized network penetration, denial-of-service attacks, or interception of private traffic is strictly prohibited under the Indian IT Act 2000, US CFAA, and international telecommunications law.</p>
    <h4>100% Free &amp; No Payments</h4>
    <p>OpticHound is 100% free open-source software. There are no subscriptions, no recurring billing, no in-app purchases, and no paid tiers.</p>
    <h4>Realistic Scope &amp; Disclaimer</h4>
    <p>OpticHound detects network-connected and wireless cameras. Standalone hidden cameras recording exclusively to offline SD cards cannot be detected via RF/network scans; always perform physical inspections as guided.</p>
    <h4>Age Requirement</h4>
    <p>OpticHound is intended for adults aged 18 and older or the age of legal majority in your jurisdiction.</p>
  `,
  cookies: `
    <h4>Zero Cookies Declaration</h4>
    <p>OpticHound does NOT use cookies of any kind. When you open this report, zero first-party cookies, zero third-party tracking cookies, and zero persistent beacons are written or read.</p>
    <h4>Exemption from Cookie Consent Banners</h4>
    <p>Under the EU ePrivacy Directive (Directive 2002/58/EC) and Indian DPDP Act 2023, cookie consent banners are only required when non-essential trackers are deployed. Because OpticHound eliminates cookies at the code level, no tracking consent banner is required.</p>
    <h4>Temporary In-Memory State</h4>
    <p>Interactive filters and searches operate solely in browser RAM and are immediately discarded when the tab is closed.</p>
  `,
  dpdp: `
    <h4>Compliance with Digital Personal Data Protection Act, 2023 (DPDP Act)</h4>
    <p>OpticHound is designed in strict accordance with Indian data protection legislation:</p>
    <ul>
      <li><strong>No External Data Fiduciary:</strong> Because OpticHound is an entirely offline, locally installed utility, the developer does not collect, receive, or host any personal data. You act as the sole controller of the tool on your own device.</li>
      <li><strong>Data Minimization (Section 6):</strong> Probing is limited strictly to local subnet surveillance ports and manufacturer OUI lookups.</li>
      <li><strong>Purpose Limitation:</strong> Processing is strictly confined to local security audit purposes.</li>
      <li><strong>Right to Erasure (Section 12):</strong> Users can permanently erase all audit data at any time simply by deleting the generated HTML or JSON file from their local drive.</li>
      <li><strong>Zero Cross-Border Transfers:</strong> No data is transmitted outside your local machine or across international borders.</li>
    </ul>
  `
}};

function openLegalModal(tab) {{
  const modal = document.getElementById('legalModal');
  modal.classList.add('active');
  showLegalTab(tab || 'privacy');
}}

function closeLegalModal() {{
  const modal = document.getElementById('legalModal');
  modal.classList.remove('active');
}}

function showLegalTab(tab) {{
  document.querySelectorAll('.modal-tabs .pill').forEach(p => p.classList.remove('active'));
  const btn = document.getElementById('tab-' + tab);
  if (btn) btn.classList.add('active');
  const body = document.getElementById('modalBody');
  if (legalContent[tab]) body.innerHTML = legalContent[tab];
}}

document.addEventListener('keydown', function(e) {{
  if (e.key === 'Escape') closeLegalModal();
}});

function renderDevices() {{
  const container = document.getElementById('devicesContainer');
  const search = document.getElementById('searchInput').value.toLowerCase();
  container.innerHTML = '';

  const filtered = devices.filter(d => {{
    // Risk Filter
    if (currentFilter === 'ALERTS' && !(d.risk_level === 'CRITICAL' || d.risk_level === 'HIGH')) return false;
    if (currentFilter === 'GLASSES') {{
      const dRole = (d.device_type || '').toLowerCase();
      if (!dRole.includes('glass') && !dRole.includes('wearable')) return false;
    }}
    if (currentFilter !== 'ALL' && currentFilter !== 'ALERTS' && currentFilter !== 'GLASSES' && d.risk_level !== currentFilter) return false;

    // Search Query
    if (search) {{
      const haystack = (d.ip + ' ' + d.mac + ' ' + d.vendor + ' ' + d.hostname + ' ' + d.http_title + ' ' + d.open_ports.join(' ')).toLowerCase();
      if (!haystack.includes(search)) return false;
    }}
    return true;
  }});

  if (filtered.length === 0) {{
    container.innerHTML = '<div style="text-align:center; padding: 40px; color: var(--text-muted);">No devices match your filter criteria.</div>';
    return;
  }}

  filtered.forEach((dev, idx) => {{
    const card = document.createElement('div');
    card.className = `device-card ${{allExpanded ? 'open' : ''}}`;
    card.id = `dev-${{idx}}`;

    let specialLabel = '';
    if (dev.is_gateway) specialLabel = '<span style="font-size:11px; color:#38bdf8; margin-left:6px;">[Gateway Router]</span>';
    if (dev.is_local) specialLabel = '<span style="font-size:11px; color:#34d399; margin-left:6px;">[Your Computer]</span>';

    // Ports Table HTML
    let portsHtml = '<p style="color:var(--text-muted); font-size:12px; margin-top:4px;">No standard camera ports open.</p>';
    if (dev.open_ports.length > 0) {{
      portsHtml = `
        <table class="ports-table">
          <thead>
            <tr>
              <th scope="col">Port</th>
              <th scope="col">Protocol / Service</th>
              <th scope="col">Banner / Response</th>
            </tr>
          </thead>
          <tbody>
            ${{dev.open_ports.map(p => `
              <tr>
                <td class="port-cell">${{p}}</td>
                <td>${{dev.port_banners[p] ? dev.port_banners[p].split('|')[0] : 'Open Service'}}</td>
                <td style="color:#cbd5e1; font-family:monospace; font-size:12px;">${{dev.port_banners[p] || 'Standard Response'}}</td>
              </tr>
            `).join('')}}
          </tbody>
        </table>
      `;
    }}

    // Evidence HTML
    let evidenceHtml = '<p style="color:var(--text-muted); font-size:12px;">No surveillance indicators detected.</p>';
    if (dev.evidence.length > 0) {{
      evidenceHtml = `
        <div class="evidence-list">
          ${{dev.evidence.map(e => `
            <div class="evidence-item">
              <span class="points-tag">+${{e.points}} pts</span>
              <div>
                <strong>${{e.description}}</strong>
                ${{e.details ? `<div style="color:var(--text-secondary); font-size:12px; margin-top:2px;">${{e.details}}</div>` : ''}}
              </div>
            </div>
          `).join('')}}
        </div>
      `;
    }}

    card.innerHTML = `
      <div class="device-header" tabindex="0" role="button" aria-expanded="${{allExpanded ? 'true' : 'false'}}" aria-controls="dev-body-${{idx}}" onclick="toggleCard(${{idx}})" onkeydown="if(event.key==='Enter'||event.key===' '){{toggleCard(${{idx}});event.preventDefault();}}">
        <div class="device-main">
          <div class="status-dot ${{dev.risk_level}}"></div>
          <div class="device-ids">
            <span class="ip-text">${{dev.ip}} ${{specialLabel}}</span>
            <span class="hostname-text">${{dev.hostname || dev.device_type || 'Connected Device'}}</span>
          </div>
          <span class="vendor-tag" style="background:#1e293b; color:#38bdf8; font-weight:600;">${{dev.device_type || 'Device'}}</span>
          <span class="vendor-tag">${{dev.vendor}}</span>
          <span class="mac-tag">${{dev.mac}}</span>
        </div>
        <div style="display:flex; align-items:center; gap:16px;">
          <span class="risk-badge ${{dev.risk_level}}">${{dev.risk_level}}</span>
          <span class="score-indicator">${{dev.score}} / 100</span>
        </div>
      </div>
      <div class="device-body" id="dev-body-${{idx}}">
        <div class="recommendation-banner ${{dev.risk_level}}">
          💡 ${{dev.recommendation}}
        </div>

        <div class="section-title">Surveillance Risk Evidence</div>
        ${{evidenceHtml}}

        <div class="section-title">Network & Service Details</div>
        <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap:10px; margin-bottom:12px; font-size:13px;">
          <div><span style="color:var(--text-secondary)">IP Address:</span> <code>${{dev.ip}}</code></div>
          <div><span style="color:var(--text-secondary)">Device Role:</span> <strong>${{dev.device_type || 'Device'}}</strong></div>
          <div><span style="color:var(--text-secondary)">MAC Address:</span> <code>${{dev.mac}}</code></div>
          <div><span style="color:var(--text-secondary)">Manufacturer:</span> ${{dev.vendor}}</div>
          <div><span style="color:var(--text-secondary)">Web Management:</span> ${{dev.http_urls.length ? `<a href="${{dev.http_urls[0]}}" target="_blank" rel="noopener noreferrer" style="color:var(--cyan-accent); text-decoration:none;">${{dev.http_urls[0]}}</a>` : 'None'}}</div>
          ${{dev.http_title ? `<div><span style="color:var(--text-secondary)">Web Title:</span> '${{dev.http_title}}'</div>` : ''}}
          ${{dev.http_server ? `<div><span style="color:var(--text-secondary)">Server Banner:</span> '${{dev.http_server}}'</div>` : ''}}
          ${{dev.rtsp_server ? `<div><span style="color:var(--text-secondary)">RTSP Server:</span> '${{dev.rtsp_server}}'</div>` : ''}}
        </div>

        <div class="section-title">Open Camera & Management Ports (${{dev.open_ports.length}})</div>
        ${{portsHtml}}

        ${{dev.snapshot_captured && dev.snapshot_b64 ? `
          <div class="section-title" style="color:var(--critical-red);">Live Camera Feed Captured</div>
          <div style="margin-top:6px; background:#0b1329; border:1px solid #ef4444; border-radius:8px; padding:12px;">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px; flex-wrap:wrap; gap:6px;">
              <span style="background:#ef4444; color:#fff; font-size:11px; font-weight:700; padding:2px 8px; border-radius:4px;">OPTICAL SNAPSHOT CAPTURED</span>
              <a href="${{dev.snapshot_url}}" target="_blank" rel="noopener noreferrer" style="font-size:12px; font-family:monospace; color:#38bdf8; text-decoration:none;">${{dev.snapshot_url}}</a>
            </div>
            <img src="${{dev.snapshot_b64}}" alt="Live camera feed snapshot captured from device at ${{dev.ip}}" style="width:100%; max-width:480px; border-radius:6px; border:1px solid #334155; display:block; cursor:pointer;" onclick="window.open(this.src)" title="Click to view full image in new tab" />
            <div style="font-size:11px; color:#94a3b8; margin-top:6px;">Unauthenticated visual frame captured directly from device HTTP endpoint.</div>
          </div>
        ` : ''}}
      </div>
    `;

    container.appendChild(card);
  }});
}}

function renderAirNetworks() {{
  const container = document.getElementById('airNetworksContainer');
  const list = document.getElementById('airListContainer');
  const badge = document.getElementById('airCountBadge');
  if (!rogueAPs || rogueAPs.length === 0) {{
    container.style.display = 'none';
    return;
  }}
  container.style.display = 'block';
  badge.innerText = `${{rogueAPs.length}} Networks`;
  list.innerHTML = rogueAPs.map(ap => `
    <div style="background:#1e293b; border-left:4px solid ${{ap.risk_level === 'CRITICAL' ? 'var(--critical-red)' : ap.risk_level === 'HIGH' ? 'var(--high-amber)' : 'var(--safe-green)'}}; padding:14px; border-radius:8px;">
      <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:8px;">
        <div style="display:flex; align-items:center; gap:10px;">
          <span class="status-dot ${{ap.risk_level}}"></span>
          <div>
            <strong style="font-size:15px; font-family:monospace;">${{ap.ssid}}</strong>
            <div style="font-size:12px; color:var(--text-muted); font-family:monospace;">BSSID: ${{ap.bssid}} | Security: ${{ap.security}} | Channel: ${{ap.channel || 'Auto'}}</div>
          </div>
        </div>
        <div style="display:flex; align-items:center; gap:12px;">
          <span style="font-size:12px; color:#38bdf8; font-family:monospace;">Signal: ${{ap.signal}}</span>
          <span class="risk-badge ${{ap.risk_level}}">${{ap.risk_level}}</span>
        </div>
      </div>
      ${{ap.evidence && ap.evidence.length > 0 ? `
        <div style="margin-top:10px; font-size:12px; color:#cbd5e1;">
          ${{ap.evidence.map(e => `<div>* <span style="color:#38bdf8;">[+${{e.points}} pts]</span> ${{e.description}}</div>`).join('')}}
        </div>
      ` : ''}}
      <div style="margin-top:8px; font-size:12px; color:#fde68a;">
        💡 ${{ap.recommendation}}
      </div>
    </div>
  `).join('');
}}

function renderWearables() {{
  const container = document.getElementById('wearablesContainer');
  const list = document.getElementById('wearablesListContainer');
  const badge = document.getElementById('wearablesCountBadge');
  if (!wearables || wearables.length === 0) {{
    container.style.display = 'none';
    return;
  }}
  container.style.display = 'block';
  badge.innerText = `${{wearables.length}} Eyewear Detected`;
  list.innerHTML = wearables.map(w => `
    <div style="background:#1e293b; border-left:4px solid ${{w.risk_level === 'CRITICAL' ? 'var(--critical-red)' : 'var(--high-amber)'}}; padding:14px; border-radius:8px;">
      <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:8px;">
        <div style="display:flex; align-items:center; gap:10px;">
          <span class="status-dot ${{w.risk_level}}"></span>
          <div>
            <strong style="font-size:15px; font-family:monospace;">${{w.device_type}}</strong>
            <div style="font-size:12px; color:var(--text-muted); font-family:monospace;">Brand: ${{w.brand}} | Signal: ${{w.signal}} | Addr: ${{w.address}}</div>
          </div>
        </div>
        <div style="display:flex; align-items:center; gap:12px;">
          <span style="font-size:12px; color:#38bdf8; font-weight:700; background:#0f172a; padding:4px 8px; border-radius:6px; border:1px solid #334155;">📍 ${{w.proximity}}</span>
          <span class="risk-badge ${{w.risk_level}}">${{w.risk_level}}</span>
        </div>
      </div>
      ${{w.evidence && w.evidence.length > 0 ? `
        <div style="margin-top:10px; font-size:12px; color:#cbd5e1;">
          ${{w.evidence.map(e => `<div>* <span style="color:#38bdf8;">[+${{e.points}} pts]</span> ${{e.description}}</div>`).join('')}}
        </div>
      ` : ''}}
      <div style="margin-top:8px; font-size:12px; color:#fde68a;">
        💡 ${{w.recommendation}}
      </div>
    </div>
  `).join('');
}}

function toggleCard(idx) {{
  const card = document.getElementById(`dev-${{idx}}`);
  if (card) {{
    card.classList.toggle('open');
    const header = card.querySelector('.device-header');
    if (header) header.setAttribute('aria-expanded', card.classList.contains('open') ? 'true' : 'false');
  }}
}}

function toggleAllCards() {{
  allExpanded = !allExpanded;
  document.querySelectorAll('.device-card').forEach(c => {{
    if (allExpanded) c.classList.add('open');
    else c.classList.remove('open');
    const header = c.querySelector('.device-header');
    if (header) header.setAttribute('aria-expanded', allExpanded ? 'true' : 'false');
  }});
}}

function setFilter(filter) {{
  currentFilter = filter;
  document.querySelectorAll('.filter-pills .pill').forEach(btn => {{
    btn.classList.remove('active');
    if (btn.innerText.startsWith(filter) || (filter === 'ALL' && btn.innerText.startsWith('All')) || (filter === 'ALERTS' && btn.innerText.startsWith('Alerts')) || (filter === 'GLASSES' && btn.innerText.startsWith('Eyewear')) || (filter === 'MEDIUM' && btn.innerText.startsWith('IoT'))) {{
      btn.classList.add('active');
    }}
  }});
  if (filter === 'GLASSES') {{
    const wSec = document.getElementById('wearablesContainer');
    if (wSec) {{
      wSec.style.display = 'block';
      wSec.scrollIntoView({{ behavior: 'smooth' }});
    }}
  }}
  renderDevices();
}}

document.getElementById('searchInput').addEventListener('input', renderDevices);

// Initial Render
renderDevices();
renderAirNetworks();
renderWearables();
</script>
</body>
</html>"""

    try:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html_content)
        return True
    except Exception as e:
        print(f"{C.RED}[!] Failed to write HTML report: {e}{C.RESET}")
        return False

# ---------------------------------------------------------------------------
# Mock Simulation Data (for testing without live rental stay devices)
# ---------------------------------------------------------------------------
MOCK_SNAPSHOT_SVG = """<svg xmlns="http://www.w3.org/2000/svg" width="480" height="270" viewBox="0 0 480 270">
  <defs>
    <radialGradient id="vig" cx="50%" cy="50%" r="65%">
      <stop offset="0%" stop-color="#1e293b"/>
      <stop offset="100%" stop-color="#020617"/>
    </radialGradient>
  </defs>
  <rect width="480" height="270" fill="url(#vig)"/>
  <!-- Room Furnishings -->
  <rect x="50" y="130" width="230" height="100" fill="#0f172a" stroke="#334155" stroke-width="2"/>
  <rect x="65" y="115" width="85" height="30" fill="#1e293b" rx="4"/>
  <rect x="175" y="115" width="85" height="30" fill="#1e293b" rx="4"/>
  <rect x="330" y="110" width="90" height="120" fill="#0f172a" stroke="#334155" stroke-width="2"/>
  <circle cx="375" cy="80" r="16" fill="#334155"/>
  <!-- Digital clock face showing spy lens location -->
  <rect x="345" y="125" width="60" height="30" fill="#020617" stroke="#ef4444" stroke-width="1.5" rx="3"/>
  <text x="352" y="144" fill="#ef4444" font-family="monospace" font-size="12" font-weight="bold">12:34</text>
  <circle cx="395" cy="140" r="3.5" fill="#38bdf8" stroke="#ef4444" stroke-width="1"/>
  <!-- Surveillance HUD Overlay -->
  <circle cx="22" cy="22" r="6" fill="#ef4444"/>
  <text x="36" y="26" fill="#ef4444" font-family="monospace" font-size="13" font-weight="bold">REC  [LIVE FEED CAPTURED]</text>
  <text x="20" y="255" fill="#38bdf8" font-family="monospace" font-size="11">CAM_01: BEDROOM_CLOCK_SPYCAM | 192.168.1.134:80/snapshot.jpg</text>
  <text x="370" y="26" fill="#94a3b8" font-family="monospace" font-size="11">1080P 30FPS</text>
  <!-- Reticle -->
  <circle cx="240" cy="135" r="45" fill="none" stroke="#38bdf8" stroke-width="1" stroke-dasharray="4 4" opacity="0.5"/>
  <line x1="220" y1="135" x2="260" y2="135" stroke="#38bdf8" stroke-width="1" opacity="0.5"/>
  <line x1="240" y1="115" x2="240" y2="155" stroke="#38bdf8" stroke-width="1" opacity="0.5"/>
</svg>"""

import base64
MOCK_SNAPSHOT_B64 = f"data:image/svg+xml;base64,{base64.b64encode(MOCK_SNAPSHOT_SVG.encode()).decode()}"

def generate_mock_rogue_aps() -> List[RogueAP]:
    return [
        RogueAP(
            ssid="Care-AP-88a21c",
            bssid="18:fe:34:88:a2:1c",
            signal="92%",
            security="Open (No Password)",
            channel="6",
            vendor="Espressif Inc (ESP32-CAM / IoT)",
            vendor_category="IOT_CHIP",
            risk_level="CRITICAL",
            score=95,
            evidence=[
                Evidence(45, "AIR_SSID", "In-Air Wi-Fi Hotspot matches spy camera pattern: 'care-ap' in 'Care-AP-88a21c'", "Default factory P2P hotspot for hidden clock and charger cameras."),
                Evidence(30, "VENDOR", "Hotspot BSSID matches hardware: Espressif Inc (ESP32-CAM / IoT)", "Ubiquitous covert spy camera chipset."),
                Evidence(20, "SECURITY", "Unencrypted Open Wi-Fi Network", "No password required to stream video."),
                Evidence(15, "PROXIMITY", "Strong Signal Strength (92%): Device in close physical proximity!", "Transmitter is located in the immediate room.")
            ],
            recommendation="ROGUE IN-AIR SPY CAMERA DETECTED. Device is broadcasting its own hotspot. Search room fixtures (clocks, chargers, smoke detectors) immediately."
        ),
        RogueAP(
            ssid="Ray-Ban-Stories-Sync-421",
            bssid="38:47:12:a9:44:11",
            signal="89%",
            security="WPA2-Personal",
            channel="6",
            vendor="Luxottica Tristar / Ray-Ban Meta",
            vendor_category="SMART_GLASSES",
            risk_level="CRITICAL",
            score=90,
            evidence=[
                Evidence(55, "AIR_SSID", "In-Air Wi-Fi Hotspot matches smart camera glasses: 'ray-ban' in 'Ray-Ban-Stories-Sync-421'", "Direct P2P Wi-Fi sync network used by Ray-Ban Meta camera glasses to offload high-resolution video clips to phone."),
                Evidence(40, "VENDOR", "Hotspot BSSID matches hardware: Luxottica Tristar / Ray-Ban Meta (38:47:12)", "Luxottica eyewear hardware manufacturing OUI prefix."),
                Evidence(15, "PROXIMITY", "Strong Signal Strength (89%): Device in close physical proximity!", "Transmitter is in the immediate room.")
            ],
            recommendation="SMART GLASSES SYNC HOTSPOT DETECTED. Ray-Ban Meta smart glasses Wi-Fi direct network detected transferring video/media. Inspect immediate room for active camera glasses."
        ),
        RogueAP(
            ssid="HD-MINI-CAM-74f0",
            bssid="a0:92:08:74:f0:11",
            signal="84%",
            security="WPA2-Personal",
            channel="1",
            vendor="Tuya Smart IoT / Mini Cam",
            vendor_category="IOT_CHIP",
            risk_level="HIGH",
            score=75,
            evidence=[
                Evidence(45, "AIR_SSID", "In-Air Wi-Fi Hotspot matches spy camera pattern: 'hd-mini' in 'HD-MINI-CAM-74f0'", "Default P2P hotspot name used by mini battery spy cameras."),
                Evidence(30, "VENDOR", "Hotspot BSSID matches hardware: Tuya Smart IoT / Mini Cam", "Smart camera transmitter."),
                Evidence(15, "PROXIMITY", "Strong Signal Strength (84%): Close physical proximity", "Located in the current suite.")
            ],
            recommendation="SUSPICIOUS WIRELESS HOTSPOT. P2P camera hotspot detected in room vicinity."
        ),
        RogueAP(
            ssid="Cabin-Guest-WiFi",
            bssid="f4:4d:5c:f7:67:4e",
            signal="98%",
            security="WPA2-Personal",
            channel="11",
            vendor="TP-Link Technologies",
            vendor_category="SMART_DISPLAY",
            risk_level="SAFE",
            score=0,
            evidence=[],
            recommendation="Primary authorized guest Wi-Fi access point."
        )
    ]

def generate_mock_wearables() -> List[WearableDevice]:
    """
    Generate realistic simulated smart glasses and AI camera eyewear
    for demonstration and testing scenarios.
    """
    return [
        WearableDevice(
            name="Ray-Ban Stories / Meta View",
            address="80:aa:1c:44:91:2f",
            device_type="Ray-Ban Meta Smart Glasses",
            brand="Luxottica Group S.p.A. / Meta",
            signal="-58 dBm (Strong)",
            proximity="Immediate Proximity (< 1.5m)",
            company_id="0x0D53",
            protocol="BLE Advertisement (Manufacturer CID 0x0D53)",
            risk_level="CRITICAL",
            score=95,
            evidence=[
                Evidence(85, "BLE_SIG", "Bluetooth SIG Manufacturer ID matches: Luxottica Group S.p.A. (0x0D53)", "Hardware manufacturer of Ray-Ban Meta & Ray-Ban Stories AI camera glasses. Contains front-facing ultra-wide camera and spatial audio recording."),
                Evidence(20, "BLE_NAME", "Bluetooth broadcast name matches camera glasses: 'Ray-Ban Stories / Meta View'", "Direct match for Ray-Ban Meta companion app sync protocol."),
                Evidence(10, "PROXIMITY", "Signal Strength -58 dBm: Immediate Proximity (< 1.5m)", "Device is actively operating in immediate physical space (worn by an individual in the room).")
            ],
            recommendation="SMART CAMERA EYEWEAR DETECTED IN IMMEDIATE VICINITY. An individual nearby is wearing or carrying Ray-Ban Meta Smart Glasses equipped with video recording capabilities. Verify recording status indicator LED."
        ),
        WearableDevice(
            name="Snap Spectacles v3",
            address="02:c4:9a:11:82:70",
            device_type="Snap Spectacles Smart Camera Glasses",
            brand="Snap Inc.",
            signal="-74 dBm (Moderate)",
            proximity="Room Vicinity (1.5 - 4m)",
            company_id="0x03C2",
            protocol="BLE Advertisement (Manufacturer CID 0x03C2)",
            risk_level="HIGH",
            score=80,
            evidence=[
                Evidence(85, "BLE_SIG", "Bluetooth SIG Manufacturer ID matches: Snap Inc. (0x03C2)", "Dual HD stereoscopic video recording camera glasses."),
                Evidence(20, "BLE_NAME", "Bluetooth broadcast name matches camera glasses: 'Snap Spectacles v3'", "Snapchat camera eyewear companion protocol.")
            ],
            recommendation="SMART CAMERA GLASSES DETECTED. Dual stereoscopic video capture device detected in the room or adjacent area."
        )
    ]

def generate_mock_devices() -> List[DeviceReport]:
    """
    Generate realistic simulated network devices representing a typical
    Airbnb / rental stay with a hidden clock camera, an IP camera, smart speakers,
    and laptops/phones.
    """
    devices = [
        # 1. Hidden Spy Cam (Tuya / Espressif disguised inside bedside clock)
        DeviceReport(
            ip="192.168.1.134",
            mac="18:fe:34:a1:88:2d",
            vendor="Espressif Inc (ESP32-CAM / IoT)",
            vendor_category="IOT_CHIP",
            hostname="tuya-clock-cam",
            device_type="Covert Clock Spy Camera",
            open_ports=[80, 554, 8080],
            port_banners={
                80: "HTTP 200 | Server: uc-httpd/1.0.0 | Title: 'Live Video Feed' | [LIVE CAMERA SNAPSHOT CAPTURED]",
                554: "RTSP Server: Hipcam RTSP Server",
                8080: "HTTP 401 | Server: Boa/0.94.14rc21 | Realm: 'IP Camera'"
            },
            http_title="Live Video Feed",
            http_server="uc-httpd/1.0.0",
            http_auth_realm="IP Camera",
            http_urls=["http://192.168.1.134:80/"],
            rtsp_active=True,
            rtsp_server="Hipcam RTSP Server v1.2",
            upnp_data={"friendly_name": "Smart Clock Camera", "model": "IPC-Mini-HD", "device_type": "urn:schemas-upnp-org:device:DigitalSecurityCamera:1"},
            snapshot_captured=True,
            snapshot_url="http://192.168.1.134:80/snapshot.jpg",
            snapshot_b64=MOCK_SNAPSHOT_B64,
            score=100,
            risk_level="CRITICAL",
            evidence=[
                Evidence(50, "SNAPSHOT", "CAPTURED LIVE CAMERA SNAPSHOT from unauthenticated endpoint: http://192.168.1.134:80/snapshot.jpg", "Unauthenticated live optical feed confirmed! Live frame captured from bedside clock."),
                Evidence(45, "STREAM", "Active RTSP Video Streaming Protocol on port 554 (Hipcam RTSP Server v1.2)", "Live RTSP stream is accessible."),
                Evidence(25, "VENDOR", "MAC OUI matched IoT/Spy Cam Chipset: Espressif Inc (ESP32-CAM)", "Heavily used in mini hidden spy cameras."),
                Evidence(35, "WEB", "Web Dashboard Title matches camera: 'Live Video Feed'", "Interface indicates direct camera view."),
                Evidence(25, "WEB", "Embedded Camera Web Server header detected: 'uc-httpd/1.0.0'", "Common embedded camera web server."),
                Evidence(30, "WEB", "Authentication Realm specifies camera: 'IP Camera'", "HTTP 401 challenge realm."),
                Evidence(35, "UPNP", "UPnP Device Descriptor identifies as camera: 'Smart Clock Camera'", "XML declares DigitalSecurityCamera.")
            ],
            recommendation="CONFIRMED SURVEILLANCE DEVICE. Immediate physical inspection recommended. Locate lens and report to booking platform if undeclared."
        ),
        # 2. Outdoor / Hallway Security Camera (Hikvision)
        DeviceReport(
            ip="192.168.1.185",
            mac="44:19:b6:54:11:90",
            vendor="Hangzhou Hikvision Digital Technology",
            vendor_category="CAM_BRAND",
            hostname="hik-ipcam-ds2cd",
            device_type="IP Security Camera",
            open_ports=[80, 554, 8000, 8899],
            port_banners={
                80: "HTTP 200 | Server: Hikvision-Web | Title: 'Hikvision Live View'",
                554: "RTSP Server: Hikvision RTSP Server",
                8000: "Hikvision Device Control Protocol Port",
                8899: "ONVIF Web Service Listener"
            },
            http_title="Hikvision Live View",
            http_server="Hikvision-Web",
            http_auth_realm="Hikvision",
            http_urls=["http://192.168.1.185:80/"],
            rtsp_active=True,
            rtsp_server="Hikvision RTSP Server",
            onvif_active=True,
            score=95,
            risk_level="CRITICAL",
            evidence=[
                Evidence(45, "STREAM", "Active RTSP Video Streaming Protocol on port 554 (Hikvision RTSP Server)", "Live streaming feed open."),
                Evidence(45, "PROTOCOL", "Responded to ONVIF WS-Discovery Probe (NetworkVideoTransmitter)", "Industry standard IP camera protocol."),
                Evidence(35, "VENDOR", "MAC OUI matched security camera brand: Hangzhou Hikvision Digital Technology", "Surveillance hardware manufacturer."),
                Evidence(35, "WEB", "Web Dashboard Title matches camera: 'Hikvision Live View'", "Surveillance web dashboard."),
                Evidence(30, "PROTOCOL", "Port 8000 Open (Hikvision Video SDK & Control Service)", "Hikvision control port.")
            ],
            recommendation="CONFIRMED SURVEILLANCE DEVICE. Check if host declared exterior/hallway cameras in listing."
        ),
        # 3. Smart Display (Amazon Echo Show with camera)
        DeviceReport(
            ip="192.168.1.42",
            mac="68:54:5a:33:41:9f",
            vendor="Ring LLC / Amazon Echo",
            vendor_category="SMART_DISPLAY",
            hostname="echo-show-kitchen",
            device_type="Smart Display (Camera/Mic)",
            open_ports=[8008, 8009, 8443],
            port_banners={8443: "HTTPS 200 | Server: Amazon-Echo"},
            http_title="Amazon Device",
            http_server="Amazon-Echo",
            score=35,
            risk_level="MEDIUM",
            evidence=[
                Evidence(15, "VENDOR", "Smart Home Device with potential camera/mic: Ring LLC / Amazon Echo", "Equipped with camera/microphone."),
                Evidence(10, "PORT", "Port 8443 Open (HTTPS Alternate)", "Local management endpoint.")
            ],
            recommendation="POTENTIAL SURVEILLANCE / SMART IOT. Device has optical camera and microphones. You may choose to cover the camera shutter."
        ),
        # 4. Gateway Router (TP-Link Archer)
        DeviceReport(
            ip="192.168.1.1",
            mac="f4:4d:5c:f7:67:4e",
            vendor="TP-Link Technologies",
            vendor_category="SMART_DISPLAY",
            hostname="tplinkwifi.net",
            device_type="Wi-Fi Router / Gateway",
            is_gateway=True,
            open_ports=[80, 443, 53],
            port_banners={80: "HTTP 200 | Server: TP-Link Router Web", 443: "HTTPS 200 | Server: TP-Link Router Web"},
            http_title="TP-Link Wireless Router",
            http_server="TP-Link Router Web",
            score=15,
            risk_level="LOW",
            evidence=[
                Evidence(10, "WEB", "Web Dashboard Open on standard port 80", "Router administration page.")
            ],
            recommendation="UNLIKELY CAMERA. Primary gateway router for local Wi-Fi internet access."
        ),
        # 5. Traveler's Own Laptop (Apple MacBook)
        DeviceReport(
            ip="192.168.1.6",
            mac="3c:06:30:12:44:fa",
            vendor="Apple Inc",
            vendor_category="BENIGN",
            hostname="MacBook-Pro.local",
            device_type="This Laptop / PC",
            is_local=True,
            open_ports=[],
            score=0,
            risk_level="SAFE",
            evidence=[],
            recommendation="BENIGN DEVICE. This is your personal laptop running the scanner."
        ),
        # 6. Guest Smartphone (iPhone)
        DeviceReport(
            ip="192.168.1.15",
            mac="02:bb:45:90:12:33",
            vendor="Private Wi-Fi MAC (Smartphone/Tablet)",
            vendor_category="RANDOMIZED",
            hostname="iPhone",
            device_type="Smartphone / Tablet",
            open_ports=[],
            score=5,
            risk_level="SAFE",
            evidence=[
                Evidence(5, "VENDOR", "Private / Randomized MAC Address", "Standard modern mobile OS privacy feature.")
            ],
            recommendation="BENIGN DEVICE. Standard guest smartphone."
        )
    ]
    return devices

# ---------------------------------------------------------------------------
# Main Scan Orchestration
# ---------------------------------------------------------------------------
def run_scan(config: ScanConfig):
    start_time = time.time()
    print_banner()

    # If mock mode is requested, immediately generate demonstration report
    if config.mock_mode:
        print(f"{C.YELLOW}{C.BOLD}[*] Running in SIMULATION / DEMO MODE (Generating realistic rental stay scenario){C.RESET}\n")
        results = generate_mock_devices()
        rogue_aps = generate_mock_rogue_aps()
        wearables = generate_mock_wearables()
        duration = 1.8

        print_terminal_report(results, config, duration, rogue_aps=rogue_aps, wearables=wearables)

        if not config.no_html:
            html_path = config.output_html or f"optichound_report_{int(time.time())}.html"
            if generate_html_report(results, config, duration, html_path, rogue_aps=rogue_aps, wearables=wearables):
                print(f"{C.GREEN}[+] Clean HTML Report saved to: {C.BOLD}{os.path.abspath(html_path)}{C.RESET}")

        if config.output_json:
            with open(config.output_json, "w") as f:
                json.dump({
                    "devices": [d.__dict__ for d in results],
                    "rogue_aps": [a.__dict__ for a in rogue_aps],
                    "wearables": [w.__dict__ for w in wearables]
                }, f, default=str, indent=2)
            print(f"{C.GREEN}[+] JSON scan results saved to: {C.BOLD}{config.output_json}{C.RESET}")
        return

    # 1. Network Auto-Detection
    print(f"{C.CYAN}[*] Step 1: Detecting network interface & local subnet...{C.RESET}")
    local_ip, subnet_cidr, iface = detect_local_network(config.interface_name, config.subnet_cidr if config.subnet_cidr != "192.168.1.0/24" else None)
    config.local_ip = local_ip
    config.subnet_cidr = subnet_cidr
    config.interface_name = iface
    config.gateway_ip = get_default_gateway()

    net = ipaddress.ip_network(subnet_cidr, strict=False)
    print(f"    • Local IP Address: {C.BOLD}{local_ip}{C.RESET}")
    print(f"    • Target Subnet:    {C.BOLD}{subnet_cidr}{C.RESET} ({net.num_addresses - 2} usable hosts)")
    if config.gateway_ip:
        print(f"    • Gateway Router:   {C.BOLD}{config.gateway_ip}{C.RESET}")
    print(f"    • Scan Mode:        {C.BOLD}{'Quick Mode (Top Camera Ports)' if config.quick_mode else 'Full Deep Mode'}{C.RESET}\n")

    # 2. Host Discovery & Subnet Ping Sweep
    print(f"{C.CYAN}[*] Step 2: Discovering active devices on Wi-Fi subnet...{C.RESET}")
    discovered_ips = set()

    # A. Active Ping / Socket Sweep
    sweep_ips, direct_arp = sweep_subnet_arp_ping(net, timeout=0.4 if config.quick_mode else 0.8, threads=config.threads)
    discovered_ips.update(sweep_ips)

    # B. Inspect OS ARP Table
    arp_table = parse_arp_cache()
    arp_table.update(direct_arp)
    for ip in arp_table.keys():
        try:
            if ipaddress.ip_address(ip) in net:
                discovered_ips.add(ip)
        except Exception:
            pass

    # Ensure local IP and Gateway are present
    if local_ip: discovered_ips.add(local_ip)
    if config.gateway_ip: discovered_ips.add(config.gateway_ip)

    # Resolve missing MACs on Windows using direct SendARP
    is_windows = "windows" in platform.system().lower()
    if is_windows:
        for ip in list(discovered_ips):
            if ip not in arp_table or arp_table[ip] == "Unknown":
                mac = win_send_arp(ip)
                if mac:
                    arp_table[ip] = mac

    # Fill local device MAC if needed
    if local_ip and (local_ip not in arp_table or arp_table[local_ip] == "Unknown"):
        try:
            import uuid
            node = uuid.getnode()
            local_mac = ':'.join(f'{(node >> i) & 0xff:02x}' for i in range(40, -1, -8))
            arp_table[local_ip] = local_mac
        except Exception:
            pass

    print(f"    • Discovered {C.BOLD}{len(discovered_ips)}{C.RESET} active IP addresses in local subnet.")

    # 3. Multicast Service Discovery (UPnP SSDP, WS-Discovery ONVIF, mDNS)
    print(f"\n{C.CYAN}[*] Step 3: Running multicast surveillance discovery (UPnP, ONVIF WS-Discovery, mDNS)...{C.RESET}")
    ssdp_cache = discover_upnp_ssdp(timeout=1.5 if config.quick_mode else 2.5)
    onvif_cache = discover_onvif_ws_discovery(timeout=1.5 if config.quick_mode else 2.5)
    mdns_cache = discover_mdns_services(timeout=1.2 if config.quick_mode else 2.0)

    for ip in ssdp_cache.keys(): discovered_ips.add(ip)
    for ip in onvif_cache.keys(): discovered_ips.add(ip)
    for ip in mdns_cache.keys(): discovered_ips.add(ip)

    if ssdp_cache:
        print(f"    • UPnP SSDP: {len(ssdp_cache)} devices responded.")
    if onvif_cache:
        print(f"    • {C.RED}{C.BOLD}ONVIF WS-Discovery: {len(onvif_cache)} cameras responded!{C.RESET}")
    if mdns_cache:
        print(f"    • mDNS / Zeroconf: {len(mdns_cache)} devices announced services.")

    # 3.5 Over-the-Air Rogue Wi-Fi Hotspot Scan
    rogue_aps: List[RogueAP] = []
    if config.air_scan:
        print(f"\n{C.CYAN}[*] Step 3.5: Scanning in-air wireless signals for rogue spy-cam hotspots...{C.RESET}")
        try:
            rogue_aps = scan_air_rogue_aps()
            suspicious_aps = [ap for ap in rogue_aps if ap.risk_level in ("CRITICAL", "HIGH")]
            if suspicious_aps:
                print(f"    • {C.BG_RED} ALERT: Found {len(suspicious_aps)} rogue spy-cam Wi-Fi hotspot(s) broadcasting nearby! {C.RESET}")
                for ap in suspicious_aps:
                    print(f"      - {C.RED}{C.BOLD}{ap.ssid}{C.RESET} ({ap.bssid}) | Signal: {ap.signal} | Security: {ap.security}")
            elif rogue_aps:
                print(f"    • Scanned {len(rogue_aps)} nearby Wi-Fi networks (No suspicious camera SSIDs detected).")
            else:
                print("    • In-air Wi-Fi scan complete (No nearby spy-cam hotspots detected or adapter not scanning).")
        except Exception:
            print("    • In-air Wi-Fi scanning skipped (Wi-Fi adapter unavailable).")

    # 3.8 Bluetooth Low Energy (BLE) Smart Glasses & Wearable Detection
    wearables: List[WearableDevice] = []
    if config.ble_scan:
        print(f"\n{C.CYAN}[*] Step 3.8: Scanning Bluetooth Low Energy (BLE) for smart glasses & AI eyewear...{C.RESET}")
        try:
            wearables = scan_ble_wearables(timeout_secs=3.0 if config.quick_mode else 5.0)
            if wearables:
                print(f"    • {C.BG_RED} ALERT: Detected {len(wearables)} AI Smart Glasses / Wearable device(s) nearby! {C.RESET}")
                for w in wearables:
                    print(f"      - {C.RED}{C.BOLD}{w.device_type}{C.RESET} ({w.brand}) | Signal: {w.signal} ({w.proximity})")
            else:
                print("    • BLE scan complete: No smart glasses or camera eyewear detected.")
        except Exception:
            print("    • BLE scan skipped (Bluetooth controller unavailable or disabled).")

    # 4. Deep Port Scanning & Fingerprinting
    target_ips = sorted(list(discovered_ips), key=lambda x: [int(p) for p in x.split(".") if p.isdigit()])
    print(f"\n{C.CYAN}[*] Step 4: Probing streaming ports, RTSP feeds & web dashboards across {len(target_ips)} devices...{C.RESET}")

    results: List[DeviceReport] = []

    def scan_worker(ip: str):
        mac = arp_table.get(ip, "Unknown")
        return scan_device(ip, mac, config, ssdp_cache, onvif_cache, mdns_cache)

    with ThreadPoolExecutor(max_workers=min(len(target_ips), 16) if target_ips else 1) as executor:
        futures = {executor.submit(scan_worker, ip): ip for ip in target_ips}
        done_count = 0
        for f in as_completed(futures):
            dev_rep = f.result()
            results.append(dev_rep)
            done_count += 1
            sys.stdout.write(f"\r    • Probed {done_count}/{len(target_ips)} devices... ")
            sys.stdout.flush()

    print("Done!")

    # Sort results by score (descending)
    results.sort(key=lambda x: x.score, reverse=True)
    duration = time.time() - start_time

    # 5. Output Reports
    print_terminal_report(results, config, duration, rogue_aps=rogue_aps, wearables=wearables)

    if not config.no_html:
        html_path = config.output_html or f"optichound_report_{int(time.time())}.html"
        if generate_html_report(results, config, duration, html_path, rogue_aps=rogue_aps, wearables=wearables):
            print(f"{C.GREEN}[+] Clean Dark-Mode HTML Report saved to: {C.BOLD}{os.path.abspath(html_path)}{C.RESET}")

    if config.output_json:
        with open(config.output_json, "w") as f:
            json.dump({
                "devices": [d.__dict__ for d in results],
                "rogue_aps": [a.__dict__ for a in rogue_aps],
                "wearables": [w.__dict__ for w in wearables]
            }, f, default=str, indent=2)
        print(f"{C.GREEN}[+] JSON results exported to: {C.BOLD}{config.output_json}{C.RESET}")

# ---------------------------------------------------------------------------
# CLI Entrypoint
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="OpticHound - Wi-Fi Hidden Camera & Surveillance Device Detector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python optichound.py
  python optichound.py --quick
  python optichound.py --subnet 192.168.1.0/24
  python optichound.py --html my_stay_report.html
  python optichound.py --mock   (Test run with realistic simulated cameras)
"""
    )
    parser.add_argument("-q", "--quick", action="store_true", help="Quick scan mode: checks high-signal camera ports with fast timeout")
    parser.add_argument("-d", "--deep", action="store_true", help="Deep scan mode: checks extended port range and banners")
    parser.add_argument("-s", "--subnet", type=str, default=None, help="Target subnet CIDR (e.g. 192.168.1.0/24). Auto-detected if omitted.")
    parser.add_argument("-i", "--interface", type=str, default=None, help="Network interface name to bind to.")
    parser.add_argument("-t", "--timeout", type=float, default=None, help="Socket timeout in seconds (default: 1.0s, quick: 0.4s).")
    parser.add_argument("--threads", type=int, default=64, help="Port scanner concurrency worker threads (default: 64).")
    parser.add_argument("--ports", type=str, default=None, help="Comma-separated custom port list to scan (e.g. 80,554,8080,37777).")
    parser.add_argument("-a", "--air-scan", action="store_true", default=True, help="Scan over-the-air Wi-Fi signals for rogue spy-cam hotspots (default: enabled)")
    parser.add_argument("--no-air-scan", action="store_false", dest="air_scan", help="Disable over-the-air rogue Wi-Fi hotspot scanning")
    parser.add_argument("-b", "--ble", action="store_true", default=True, help="Scan Bluetooth Low Energy (BLE) advertisements for smart glasses (default: enabled)")
    parser.add_argument("--no-ble", action="store_false", dest="ble_scan", help="Disable Bluetooth Low Energy smart glasses scan")
    parser.add_argument("--snapshots", action="store_true", default=True, help="Audit open camera ports for live unauthenticated snapshots (default: enabled)")
    parser.add_argument("--no-snapshots", action="store_false", dest="snapshots", help="Disable camera snapshot auditing")
    parser.add_argument("-o", "--html", type=str, default=None, help="Custom file path for the generated dark-mode HTML report.")
    parser.add_argument("--no-html", action="store_true", help="Disable HTML report generation.")
    parser.add_argument("--json", type=str, default=None, help="Save structured scan results to a JSON file.")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI terminal colors.")
    parser.add_argument("--mock", action="store_true", help="Run in simulation/demonstration mode with realistic hidden cameras.")

    args = parser.parse_args()

    if args.no_color:
        global C
        C = Colors(enabled=False)

    custom_ports = None
    if args.ports:
        try:
            custom_ports = [int(p.strip()) for p in args.ports.split(",") if p.strip()]
        except ValueError:
            print(f"{C.RED}[!] Error: Invalid port numbers in --ports argument.{C.RESET}")
            sys.exit(1)

    timeout = args.timeout or (0.5 if args.quick else 1.0)

    config = ScanConfig(
        subnet_cidr=args.subnet or "192.168.1.0/24",
        interface_name=args.interface or "Default",
        quick_mode=args.quick,
        deep_mode=args.deep,
        timeout=timeout,
        threads=args.threads,
        custom_ports=custom_ports,
        air_scan=args.air_scan,
        ble_scan=args.ble_scan,
        snapshot_audit=args.snapshots,
        output_html=args.html,
        no_html=args.no_html,
        output_json=args.json,
        mock_mode=args.mock
    )

    try:
        run_scan(config)
    except KeyboardInterrupt:
        print(f"\n{C.YELLOW}[!] Scan interrupted by user. Exiting.{C.RESET}")
        sys.exit(0)

if __name__ == "__main__":
    main()
