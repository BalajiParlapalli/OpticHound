"""
Test suite for OpticHound - Hidden Camera & Surveillance Detector.
Verifies OUI matching, risk scoring, protocol probing, HTML report generation, and CLI.
"""

import os
import sys
import tempfile
import unittest
import ipaddress

# Add parent directory to sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from optichound import (
    lookup_vendor,
    normalize_mac,
    is_randomized_mac,
    evaluate_device_risk,
    generate_html_report,
    DeviceReport,
    Evidence,
    ScanConfig,
    generate_mock_devices,
    generate_mock_rogue_aps,
    PORT_SIGNATURES,
    CAMERA_PORTS_QUICK,
    SNAPSHOT_PATHS,
    SPY_CAM_SSID_KEYWORDS,
    RogueAP
)


class TestOUIAndVendor(unittest.TestCase):
    def test_normalize_mac(self):
        self.assertEqual(normalize_mac("18-FE-34-A1-88-2D"), "18:fe:34:a1:88:2d")
        self.assertEqual(normalize_mac("18fe34a1882d"), "18:fe:34:a1:88:2d")
        self.assertEqual(normalize_mac("18:fe:34:a1:88:2d"), "18:fe:34:a1:88:2d")

    def test_randomized_mac_detection(self):
        # Locally administered bit is 0x02 on first byte
        self.assertTrue(is_randomized_mac("02:bb:45:90:12:33"))
        self.assertTrue(is_randomized_mac("da:a1:19:22:33:44"))
        # Universal / OUI assigned MAC (bit 0x02 is 0)
        self.assertFalse(is_randomized_mac("00:12:12:33:44:55"))
        self.assertFalse(is_randomized_mac("18:fe:34:aa:bb:cc"))

    def test_surveillance_vendor_lookups(self):
        # Hikvision
        vendor, cat, weight = lookup_vendor("00:12:12:aa:bb:cc")
        self.assertIn("Hikvision", vendor)
        self.assertEqual(cat, "CAM_BRAND")
        self.assertGreaterEqual(weight, 30)

        # Dahua
        vendor, cat, weight = lookup_vendor("00:1a:07:11:22:33")
        self.assertIn("Dahua", vendor)
        self.assertEqual(cat, "CAM_BRAND")

        # Wyze
        vendor, cat, weight = lookup_vendor("2c:aa:8e:00:11:22")
        self.assertIn("Wyze", vendor)
        self.assertEqual(cat, "CAM_BRAND")

        # Espressif (DIY hidden spy camera chipset)
        vendor, cat, weight = lookup_vendor("18:fe:34:99:88:77")
        self.assertIn("Espressif", vendor)
        self.assertEqual(cat, "IOT_CHIP")

        # Tuya Smart (budget mini spy cams)
        vendor, cat, weight = lookup_vendor("10:5a:f7:12:34:56")
        self.assertIn("Tuya", vendor)
        self.assertEqual(cat, "IOT_CHIP")

        # Xiongmai (Sofia protocol spy cam boards)
        vendor, cat, weight = lookup_vendor("00:12:15:33:22:11")
        self.assertIn("Xiongmai", vendor)
        self.assertEqual(cat, "CAM_BRAND")

        # Randomized MAC
        vendor, cat, weight = lookup_vendor("02:aa:bb:cc:dd:ee")
        self.assertEqual(cat, "RANDOMIZED")

        # Unknown
        vendor, cat, weight = lookup_vendor("99:99:99:11:22:33")
        self.assertEqual(cat, "BENIGN")


class TestRiskScoringEngine(unittest.TestCase):
    def test_critical_confirmed_camera(self):
        # Device with active RTSP feed and Hikvision OUI
        dev = DeviceReport(
            ip="192.168.1.185",
            mac="44:19:b6:54:11:90",
            vendor="Hangzhou Hikvision Digital Technology",
            vendor_category="CAM_BRAND",
            open_ports=[80, 554, 8000],
            rtsp_active=True,
            rtsp_server="Hikvision RTSP Server",
            http_title="Hikvision Live View"
        )
        evaluated = evaluate_device_risk(dev)
        self.assertEqual(evaluated.risk_level, "CRITICAL")
        self.assertGreaterEqual(evaluated.score, 85)
        # Check evidence categories
        categories = [e.category for e in evaluated.evidence]
        self.assertIn("STREAM", categories)
        self.assertIn("VENDOR", categories)
        self.assertIn("WEB", categories)

    def test_covert_tuya_spy_camera(self):
        # Typical covert spy camera disguised inside a bedside clock
        dev = DeviceReport(
            ip="192.168.1.134",
            mac="18:fe:34:a1:88:2d",
            vendor="Espressif Inc (ESP32-CAM / IoT)",
            vendor_category="IOT_CHIP",
            open_ports=[80, 554, 8080],
            rtsp_active=True,
            rtsp_server="Hipcam RTSP",
            http_title="Live Video Feed",
            http_server="uc-httpd/1.0.0",
            http_auth_realm="IP Camera"
        )
        evaluated = evaluate_device_risk(dev)
        self.assertEqual(evaluated.risk_level, "CRITICAL")
        self.assertGreaterEqual(evaluated.score, 85)

    def test_xiongmai_surveillance_protocol(self):
        # Xiongmai port 34567 open
        dev = DeviceReport(
            ip="192.168.1.200",
            mac="00:12:15:22:33:44",
            vendor="Hangzhou Xiongmai Technology",
            vendor_category="CAM_BRAND",
            open_ports=[34567, 80]
        )
        evaluated = evaluate_device_risk(dev)
        self.assertIn(evaluated.risk_level, ["HIGH", "CRITICAL"])
        self.assertGreaterEqual(evaluated.score, 60)

    def test_smart_speaker_display(self):
        # Amazon Echo Show
        dev = DeviceReport(
            ip="192.168.1.42",
            mac="68:54:5a:33:41:9f",
            vendor="Ring LLC / Amazon Echo",
            vendor_category="SMART_DISPLAY",
            open_ports=[8443]
        )
        evaluated = evaluate_device_risk(dev)
        self.assertEqual(evaluated.risk_level, "MEDIUM")
        self.assertGreaterEqual(evaluated.score, 25)

    def test_gateway_router_dampening(self):
        # Router with port 80 open should not be flagged as a critical camera
        dev = DeviceReport(
            ip="192.168.1.1",
            mac="f4:4d:5c:f7:67:4e",
            vendor="TP-Link Technologies",
            vendor_category="SMART_DISPLAY",
            is_gateway=True,
            open_ports=[80, 443],
            http_title="TP-Link Router Admin"
        )
        evaluated = evaluate_device_risk(dev)
        self.assertIn(evaluated.risk_level, ["LOW", "SAFE"])
        self.assertLessEqual(evaluated.score, 25)

    def test_benign_personal_computer(self):
        # Laptop
        dev = DeviceReport(
            ip="192.168.1.6",
            mac="3c:06:30:12:44:fa",
            vendor="Apple Inc",
            vendor_category="BENIGN",
            is_local=True,
            open_ports=[]
        )
        evaluated = evaluate_device_risk(dev)
        self.assertEqual(evaluated.risk_level, "SAFE")
        self.assertEqual(evaluated.score, 0)


class TestHTMLReportGeneration(unittest.TestCase):
    def test_html_report_creates_valid_file(self):
        devices = generate_mock_devices()
        config = ScanConfig(subnet_cidr="192.168.1.0/24")

        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            success = generate_html_report(devices, config, duration=2.5, filepath=tmp_path)
            self.assertTrue(success)
            self.assertTrue(os.path.exists(tmp_path))

            with open(tmp_path, "r", encoding="utf-8") as f:
                content = f.read()

            # Verify crucial components
            self.assertIn("OpticHound Surveillance Audit", content)
            self.assertIn("192.168.1.134", content)  # Hidden spy cam
            self.assertIn("18:fe:34:a1:88:2d", content)
            self.assertIn("CRITICAL", content)
            self.assertIn("Traveler's Physical Inspection Guide", content)
            self.assertIn("const devices =", content)
            self.assertIn("searchInput", content)
            self.assertIn("toggleCard", content)
            self.assertIn("setFilter", content)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)


class TestPortSignatures(unittest.TestCase):
    def test_camera_ports_present(self):
        self.assertIn(554, PORT_SIGNATURES)  # RTSP
        self.assertIn(8554, PORT_SIGNATURES)
        self.assertIn(37777, PORT_SIGNATURES) # Dahua
        self.assertIn(34567, PORT_SIGNATURES) # Xiongmai
        self.assertIn(8000, PORT_SIGNATURES)  # Hikvision
        self.assertIn(8899, PORT_SIGNATURES)  # ONVIF

    def test_quick_ports_subset(self):
        for p in CAMERA_PORTS_QUICK:
            self.assertIn(p, PORT_SIGNATURES)


class TestAddonSnapshotAndRogueAP(unittest.TestCase):
    def test_snapshot_paths_integrity(self):
        # Critical camera snapshot endpoints must be defined
        self.assertIn("/snapshot.jpg", SNAPSHOT_PATHS)
        self.assertIn("/jpg/image.jpg", SNAPSHOT_PATHS)
        self.assertIn("/webcapture.jpg", SNAPSHOT_PATHS)
        self.assertIn("/snap.jpg", SNAPSHOT_PATHS)

    def test_snapshot_risk_scoring_boost(self):
        # Device where snapshot was successfully captured
        dev = DeviceReport(
            ip="192.168.1.55",
            mac="18:fe:34:22:11:00",
            vendor="Espressif Inc (ESP32-CAM / IoT)",
            vendor_category="IOT_CHIP",
            open_ports=[80],
            snapshot_captured=True,
            snapshot_url="http://192.168.1.55:80/snapshot.jpg",
            snapshot_b64="data:image/jpeg;base64,/9j/4AAQSkZJRg=="
        )
        evaluated = evaluate_device_risk(dev)
        # Snapshot capture is definitive optical proof
        self.assertEqual(evaluated.risk_level, "CRITICAL")
        self.assertGreaterEqual(evaluated.score, 75)
        categories = [e.category for e in evaluated.evidence]
        self.assertIn("SNAPSHOT", categories)
        snapshot_ev = [e for e in evaluated.evidence if e.category == "SNAPSHOT"][0]
        self.assertEqual(snapshot_ev.points, 50)

    def test_spy_cam_ssid_heuristics(self):
        # Popular spy camera default SSIDs
        cam_ssids = [
            "Care-AP-88a21c",
            "HD-MINI-CAM-74f0",
            "LOOKCAM_98124A",
            "IPCAM-38291",
            "ESP32-CAM-AP",
            "v380_camera_setup",
            "xiaovv-live-feed",
            "clock_cam_wifi",
            "spy-gadget-direct"
        ]
        for ssid in cam_ssids:
            matches = [kw for kw in SPY_CAM_SSID_KEYWORDS if kw in ssid.lower()]
            self.assertTrue(len(matches) > 0, f"Expected SSID '{ssid}' to match spy cam keywords")

    def test_benign_ssid_no_false_positives(self):
        benign_ssids = [
            "NETGEAR_Home_5G",
            "Starbucks_Guest_WiFi",
            "Marriott_Bonvoy_HighSpeed",
            "SmithFamily2024",
            "GoogleFiber_100",
            "iPhone_Hotspot"
        ]
        for ssid in benign_ssids:
            matches = [kw for kw in SPY_CAM_SSID_KEYWORDS if kw in ssid.lower()]
            self.assertEqual(len(matches), 0, f"Benign SSID '{ssid}' should not match spy cam keywords")

    def test_mock_rogue_aps_generation(self):
        aps = generate_mock_rogue_aps()
        self.assertGreaterEqual(len(aps), 2)
        critical_aps = [ap for ap in aps if ap.risk_level == "CRITICAL"]
        self.assertTrue(len(critical_aps) >= 1)
        self.assertIn("Espressif", critical_aps[0].vendor)

    def test_html_includes_snapshots_and_rogue_aps(self):
        devices = generate_mock_devices()
        rogue_aps = generate_mock_rogue_aps()
        config = ScanConfig(subnet_cidr="192.168.1.0/24")

        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            success = generate_html_report(devices, config, duration=1.2, filepath=tmp_path, rogue_aps=rogue_aps)
            self.assertTrue(success)
            with open(tmp_path, "r", encoding="utf-8") as f:
                html = f.read()
            self.assertIn("Snapshots Captured", html)
            self.assertIn("In-Air Rogue APs", html)
            self.assertIn("Care-AP-88a21c", html)
            self.assertIn("HD-MINI-CAM-74f0", html)
            self.assertIn("OPTICAL SNAPSHOT CAPTURED", html)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_accessibility_and_contrast(self):
        devices = generate_mock_devices()
        config = ScanConfig(subnet_cidr="192.168.1.0/24")

        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            generate_html_report(devices, config, duration=1.0, filepath=tmp_path)
            with open(tmp_path, "r", encoding="utf-8") as f:
                html = f.read()

            # Contrast & Focus
            self.assertIn("--text-muted: #94a3b8", html)
            self.assertIn(":focus-visible", html)
            self.assertIn(".sr-only", html)

            # Keyboard accessibility & ARIA
            self.assertIn('aria-label="Search devices by IP, MAC, Brand, Port, or Web Title"', html)
            self.assertIn('aria-label="Filter: Show all devices"', html)
            self.assertIn('aria-label="Filter: Show critical risk cameras"', html)
            self.assertIn('tabindex="0"', html)
            self.assertIn('role="button"', html)
            self.assertIn("event.key==='Enter'", html)

            # Image alt text
            self.assertIn('alt="Live camera feed snapshot captured from device', html)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_privacy_and_compliance(self):
        devices = generate_mock_devices()
        config = ScanConfig(subnet_cidr="192.168.1.0/24")

        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            generate_html_report(devices, config, duration=1.0, filepath=tmp_path)
            with open(tmp_path, "r", encoding="utf-8") as f:
                html = f.read()

            # Zero tracking & offline guarantees
            self.assertNotIn("fonts.googleapis.com", html)
            self.assertNotIn("google-analytics.com", html)
            self.assertNotIn("googletagmanager.com", html)
            self.assertNotIn("clarity.ms", html)
            self.assertNotIn("hotjar.com", html)
            self.assertNotIn("fullstory.com", html)

            # Legal & Privacy integration
            self.assertIn("openLegalModal('privacy')", html)
            self.assertIn("openLegalModal('terms')", html)
            self.assertIn("openLegalModal('cookies')", html)
            self.assertIn("openLegalModal('dpdp')", html)
            self.assertIn("Digital Personal Data Protection Act", html)
            self.assertIn("100% Local • Zero Telemetry", html)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_policy_documents_exist(self):
        base_dir = os.path.dirname(os.path.abspath(__file__))
        self.assertTrue(os.path.exists(os.path.join(base_dir, "PRIVACY.md")))
        self.assertTrue(os.path.exists(os.path.join(base_dir, "TERMS.md")))
        self.assertTrue(os.path.exists(os.path.join(base_dir, "COOKIE_POLICY.md")))
        self.assertTrue(os.path.exists(os.path.join(base_dir, "SECURITY.md")))


if __name__ == "__main__":
    unittest.main()
