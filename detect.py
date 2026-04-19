#!/usr/bin/env python3
"""
detect.py -- Detect keylogger and input interception apps
Scans for: OnKeyListener, accessibility services, IME apps,
suspicious permission patterns.
Usage: python3 detect.py [--suspicious]
"""
import subprocess, re, sys

DANGEROUS_PERMISSIONS = {
    "android.permission.RECORD_AUDIO": "Can record all audio (mic)",
    "android.permission.CAMERA": "Can access camera",
    "android.permission.READ_CLIPBOARD": "Can read clipboard (passwords, tokens)",
    "android.permission.BIND_ACCESSIBILITY_SERVICE": "Full input interception",
    "android.permission.MODIFY_AUDIO_SETTINGS": "Can modify audio routing",
}

SUSPICIOUS_PACKAGES = [
    "com.termux",  # Terminal emulator (can run keylogger)
    "com.android.inputmethod",  # Custom keyboards
    "xda.labs",  # Xposed framework
]

def adb(cmd):
    r = subprocess.run(f"adb shell {cmd}", shell=True, capture_output=True, text=True)
    return r.stdout.strip()

def get_packages():
    out = adb("pm list packages")
    return [l.split(":")[1] for l in out.splitlines() if l.startswith("package:")]

def get_permissions(pkg):
    out = adb(f"dumpsys package {pkg}")
    perms = []
    for line in out.splitlines():
        if "android.permission" in line:
            m = re.search(r'(android\.permission\.\w+)', line)
            if m:
                perms.append(m.group(1))
    return list(set(perms))

def get_accessibility_services():
    out = adb("settings get secure enabled_accessibility_services")
    return out.split(":") if out else []

def main():
    print("\n⌨️  Android Keylogger Detector")
    print("=" * 50)

    packages = get_packages()
    print(f"Scanning {len(packages)} installed apps...\n")

    risky = []

    # Check accessibility services
    print("[Accessibility Services]")
    a11y = get_accessibility_services()
    for svc in a11y:
        pkg = svc.split("/")[0] if "/" in svc else svc
        print(f"  ⚠️  {pkg} (full input access)")
        risky.append((pkg, "Accessibility Service"))

    # Check permissions
    print("\n[Permission Scan]")
    for pkg in packages:
        perms = get_permissions(pkg)
        risky_perms = [p for p in perms if p in DANGEROUS_PERMISSIONS]
        
        if len(risky_perms) >= 2:  # Multiple dangerous perms = suspicious
            print(f"  ⚠️  {pkg.split('.')[-1]}")
            for p in risky_perms:
                print(f"       {p.split('.')[-1]} - {DANGEROUS_PERMISSIONS.get(p, '')}")
            risky.append((pkg, "Multiple dangerous permissions"))

    # Check suspicious packages
    print("\n[Known Risk Packages]")
    for pkg in SUSPICIOUS_PACKAGES:
        if pkg in packages:
            print(f"  🚨 {pkg} (high risk tool)")
            risky.append((pkg, "High-risk app type"))

    print("\n" + "=" * 50)
    print(f"Found {len(risky)} apps of concern")
    print("\nRecommendation:")
    print("  1. Review accessibility services (Settings → Accessibility)")
    print("  2. Disable permissions for suspicious apps")
    print("  3. Consider uninstalling high-risk tools")

if __name__ == "__main__":
    main()
