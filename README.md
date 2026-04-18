# ⌨️ Android Keylogger Detector

Scan for and block apps that intercept keyboard input on your Android device.

## What it detects
- Accessibility services that can read input
- Input method editors (IME) that log keystrokes
- Apps hooking KeyEvent via Frida/Xposed
- Shell-level input monitoring

## Usage
```bash
python3 detect.py              # Full scan
python3 detect.py --block      # Block suspicious apps
python3 detect.py --watch      # Monitor for new input hooks in real-time
```
