# ⌨️ Android Keylogger Detector

Detect potential keylogger and event listener apps that intercept keyboard/touch input.

## Usage

```bash
python3 detect.py                   # Scan all apps
python3 detect.py --suspicious      # Focus on high-risk apps
python3 detect.py --export json     # Export findings
```

## Detection methods

1. **OnKeyListener hooks** — detects apps registering global key listeners
2. **Accessibility service** — apps with BIND_ACCESSIBILITY_SERVICE
3. **Input method editors** — IME apps that process all typed text
4. **Permission pattern matching** — apps with unusual READ/RECORD permissions
5. **Native library analysis** — libc hooks via strace/ltrace
