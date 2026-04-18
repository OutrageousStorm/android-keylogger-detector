#!/usr/bin/env python3
"""
detect.py -- Scan for keyboard input interception on Android
Identifies accessibility services, IMEs, and Frida hooks that could log keystrokes.
"""
import subprocess, re, sys

def adb(cmd):
    r = subprocess.run(f"adb shell {cmd}", shell=True, capture_output=True, text=True)
    return r.stdout.strip()

def check_accessibility():
    """Find accessibility services enabled"""
    out = adb("settings get secure enabled_accessibility_services")
    if out and out != "null":
        services = out.split(":")
        return services
    return []

def check_ime():
    """Find installed input methods"""
    out = adb("settings get secure default_input_method")
    return [out] if out and out != "null" else []

def check_frida_hooks():
    """Look for Frida/Xposed in process maps (requires logcat monitoring)"""
    out = adb("logcat -d | grep -i 'frida\|xposed\|substrate'")
    return out.splitlines() if out else []

def check_input_monitoring():
    """Check if any app is monitoring /dev/input"""
    out = adb("lsof | grep '/dev/input'")
    return out.splitlines() if out else []

def get_app_label(pkg):
    """Get app name for a package"""
    out = adb(f"pm dump {pkg} | grep 'versionName' | head -1")
    return pkg.split(".")[-1]

def main():
    print("\n⌨️  Android Keylogger Detector")
    print("=" * 50)

    print("\n[1/4] Checking accessibility services...")
    a11y = check_accessibility()
    if a11y:
        print(f"  ⚠️  Found {len(a11y)} enabled accessibility service(s):")
        for svc in a11y:
            label = get_app_label(svc)
            print(f"    - {label} ({svc})")
    else:
        print("  ✅ No suspicious accessibility services")

    print("\n[2/4] Checking input methods...")
    ime = check_ime()
    if ime:
        print(f"  ⚠️  Default IME: {ime[0]}")
    else:
        print("  ✅ No non-standard IME")

    print("\n[3/4] Checking for Frida/Xposed hooks...")
    frida = check_frida_hooks()
    if frida:
        print(f"  ⚠️  Found {len(frida)} suspicious log entries")
        for line in frida[:3]:
            print(f"    {line[:60]}")
    else:
        print("  ✅ No Frida/Xposed hooks detected")

    print("\n[4/4] Checking /dev/input access...")
    input_access = check_input_monitoring()
    if input_access:
        print(f"  ⚠️  {len(input_access)} process(es) accessing /dev/input")
    else:
        print("  ✅ No apps hooked into input")

    print("\n" + "=" * 50)
    total_sus = len(a11y) + len(ime) + len(frida) + len(input_access)
    if total_sus == 0:
        print("✅ Scan complete. No keylogger signatures detected.")
    else:
        print(f"⚠️  Scan complete. Found {total_sus} potential issues.")
        print("\nRecommendations:")
        print("  - Review accessibility services: check what they actually do")
        print("  - Use a privacy-hardened ROM (GrapheneOS, CalyxOS)")
        print("  - Consider rooting with Shamiko to hide root from spyware")

if __name__ == "__main__":
    main()
