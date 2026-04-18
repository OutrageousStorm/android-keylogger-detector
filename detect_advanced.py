#!/usr/bin/env python3
"""
detect_advanced.py -- Detect keylogger and input spy apps via ADB analysis
Analyzes: permissions, accessibility services, input device access, network activity
Usage: python3 detect_advanced.py
"""
import subprocess, re, json

SUSPICIOUS_PERMS = [
    "android.permission.RECORD_AUDIO",
    "android.permission.GET_TASKS",
    "android.permission.READ_CLIPBOARD",
    "android.permission.MONITOR_INPUT",
    "android.permission.CAPTURE_VIDEO_OUTPUT",
]

SUSPICIOUS_SERVICES = [
    "AccessibilityService", "InputMethodService",
    "android.view.inputmethod.InputMethod",
]

KNOWN_LEGIT_KEYBOARD = [
    "com.google.android.inputmethod.latin",
    "com.android.inputmethod",
    "com.samsung.android.honeyboard",
]

def adb(cmd):
    r = subprocess.run(f"adb shell {cmd}", shell=True, capture_output=True, text=True)
    return r.stdout.strip()

def get_accessibility_services():
    out = adb("settings get secure enabled_accessibility_services")
    return out.split(':') if out else []

def analyze_app_perms(pkg):
    out = adb(f"dumpsys package {pkg}")
    perms = []
    for line in out.splitlines():
        if "granted=true" in line.lower():
            for perm in SUSPICIOUS_PERMS:
                if perm in line:
                    perms.append(perm.split('.')[-1])
    return perms

def get_input_method():
    out = adb("settings get secure default_input_method")
    return out

def analyze_network(pkg):
    """Check network connections from app"""
    out = adb(f"netstat -tulnp 2>/dev/null | grep {pkg} || echo 'none'")
    return "Yes" if out and out != "none" else "No"

def scan_for_keyloggers():
    print("\n🔍 Android Keylogger & Input Spy Detector")
    print("=" * 50)

    # Check accessibility services (prime suspect for keylogging)
    print("\n[1] Accessibility Services (can intercept input):")
    services = get_accessibility_services()
    print(f"  Enabled: {services or 'None'}")
    risk = "HIGH" if services else "LOW"
    print(f"  Risk: {risk}")

    # Check input method
    print("\n[2] Current Input Method (keyboard):")
    ime = get_input_method()
    pkg = ime.split('/')[ 0] if ime else ""
    is_legit = any(l in pkg for l in KNOWN_LEGIT_KEYBOARD)
    print(f"  Package: {pkg}")
    print(f"  Trusted: {'Yes ✓' if is_legit else 'Unknown ⚠️ '}")

    # Scan installed apps
    print("\n[3] Scanning all apps for suspicious permissions...")
    pkgs = adb("pm list packages")
    suspicious_apps = []

    for line in pkgs.splitlines():
        pkg_name = line.replace("package:", "").strip()
        if not pkg_name:
            continue
        perms = analyze_app_perms(pkg_name)
        if len(perms) >= 2:  # 2+ suspicious perms = flag it
            net = analyze_network(pkg_name)
            suspicious_apps.append({
                "pkg": pkg_name,
                "perms": perms,
                "network": net,
                "risk_score": len(perms) * 25 + (25 if net == "Yes" else 0)
            })

    if suspicious_apps:
        suspicious_apps.sort(key=lambda x: x["risk_score"], reverse=True)
        print(f"\n  Found {len(suspicious_apps)} suspicious apps:\n")
        for i, app in enumerate(suspicious_apps[:10]):
            risk_level = "🔴 HIGH" if app["risk_score"] >= 75 else "🟡 MEDIUM" if app["risk_score"] >= 50 else "🟢 LOW"
            label = app["pkg"].split('.')[-1]
            print(f"  {risk_level} {label}")
            print(f"       Suspicious perms: {', '.join(app['perms'])}")
            print(f"       Network activity: {app['network']}")
            print()
    else:
        print("  ✓ No highly suspicious apps detected")

    print("=" * 50)
    print("⚠️  Note: This is a heuristic scan. Manual review recommended.")

if __name__ == "__main__":
    scan_for_keyloggers()
