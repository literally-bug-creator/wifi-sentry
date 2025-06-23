# 🔐 WifiSentry

A **CLI-based** tool for **passive vulnerability scanning and risk assessment of Wi-Fi networks**.

# 🎯 About

**_WifiSentry_** is an **educational project** focused on **Wi-Fi network security analysis**. It provides a CLI to perform **passive monitoring and detect suspicious behavior in nearby wireless networks**.

# 🧰 Features

- [ ] Passive (non-intrusive) scanning of nearby access points and clients
- [ ] Detection of common Wi-Fi vulnerabilities and anomalies
- [ ] Risk scoring system (1–10) based on detected patterns

# 📌 Detected Vulnerabilities

- [ ] 🔓 **Open Network** - High risk of sniffing and MITM attacks
- [ ] 🤖 **WPS Enabled** - Susceptible to PIN brute-force attacks
- [ ] 🧠 **Hidden SSID** - May hide malicious access points
- [ ] 🦹 **Evil Twin Candidates** - Duplicate SSIDs with suspicious signal strength
- [ ] 📡 **Multi-channel AP** - Possible rogue access point behavior
- [ ] 🧨 **Deauth/Disassoc Floods** - Indicator of DoS or handshake capture attempts
- [ ] 📜 **Handshake/PMKID Capture** - Potential offline password cracking
- [ ] 🧬 **MAC Vendor Mismatch** - Signs of spoofing or fake APs
- [ ] 🔍 **Abnormal Beacon Intervals** - May indicate custom/fake firmware
- [ ] 🕵️ **Client Probe Requests** - Privacy leak: reveals previously connected networks

# 📊 Risk Scoring System

## Indicator Scoring

| Indicator                                                            | Points     | Comment                                              |
| -------------------------------------------------------------------- | ---------- | ---------------------------------------------------- |
| **Open network**                                                     | +7         | Highest danger — anyone can eavesdrop                |
| **WPS enabled**                                                      | +5         | Can be exploited within hours (if PIN is insecure)   |
| **Handshake/PMKID capture possible**                                 | +6         | High risk if password is weak                        |
| **Abnormally strong signal from a duplicate SSID**                   | +4         | Sign of an Evil Twin attack                          |
| **Duplicate SSID (2+ APs with the same name)**                       | +3         | May indicate an attack (or legitimate mesh/repeater) |
| **Broadcasting on multiple channels simultaneously**                 | +3         | Sign of a rogue AP                                   |
| **Frequent deauth/disassoc packets**                                 | +4         | Clear DoS or Evil Twin preparation                   |
| **MAC doesn't match vendor OUI (vendor mismatch)**                   | +2         | Often indicates a spoofed MAC                        |
| **Hidden SSID**                                                      | +1         | Not dangerous by itself, but suspicious              |
| **Unusual beacon intervals (<50 or >500 ms)**                        | +1         | Could be a fake AP                                   |
| **Client probe requests visible**                                    | +1         | Indicates history leakage, doesn't threaten the AP   |
| **Strong signal difference between SSID duplicates**                 | +2         | Confirms Evil Twin activity                          |
| **Many similar-looking SSIDs ("Free_WiFi", "FreeWiFi", "FrееWiFi")** | +3         | SSID flooding / phishing attempt                     |
| **Open network + duplicate SSID with encryption**                    | +3 (extra) | Combined attack (fake portal + MITM)                 |

## Final Network Risk Score

| Total Score | 10-Point Scale Rating | Risk Level      |
| ----------- | --------------------- | --------------- |
| 0–4         | 1–2                   | Safe / Low Risk |
| 5–8         | 3–4                   | Minor Risk      |
| 9–13        | 5–6                   | Medium Risk     |
| 14–18       | 7–8                   | High Risk       |
| 19+         | 9–10                  | Critical Danger |
