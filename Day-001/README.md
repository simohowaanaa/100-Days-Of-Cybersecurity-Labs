# Day-001 — Lockdown Lab

| | |
|---|---|
| **Plateforme** | [CyberDefenders](https://cyberdefenders.org/blueteam-ctf-challenges/lockdown/) |
| **Catégorie** | Network Forensics |
| **Difficulté** | Easy |
| **Durée estimée** | ~1h |
| **Date** | 2026-08-11 |
| **Outils** | Wireshark / tshark · capinfos · Volatility 3 · FLOSS / strings · VirusTotal |

> ⚠️ **Lab actif — writeup méthodologique.** Conformément aux règles de CyberDefenders (« Writeups are not allowed for active labs »), ce document décrit **uniquement la démarche, les outils et les filtres**. Les réponses/flags sont **volontairement masqués** (texte et captures floutées). Objectif : partager la *méthode*, pas les solutions.

---

## 🎯 Scénario

Le SOC de **TechNova Systems** a détecté du trafic sortant suspect depuis un **serveur IIS** exposé sur Internet — signe d'un dépôt de web-shell et de connexions vers un hôte inconnu.

En tant qu'examinateur forensic, je dispose de **3 artefacts** :

| Artefact | Type | Rôle |
|---|---|---|
| `capture.pcapng` | Trafic réseau (~3.8 Mo) | Ce qui s'est passé sur le réseau |
| `memdump.mem` | Image mémoire RAM (~4.7 Go) | L'état du serveur pendant l'attaque |
| `updatenow.exe` | Malware (~588 Ko) | Le binaire malveillant récupéré sur disque |

**Objectif :** reconstruire l'intégralité de l'intrusion et la mapper à MITRE ATT&CK.

---

## 🧭 Kill Chain reconstruite

```
Reconnaissance (scan)  →  Énumération HTTP  →  Accès SMB (partages)
        →  Dépôt web-shell  →  Reverse shell
        →  Persistance (implant)  →  Command & Control (C2 / RAT)
```

---

# 🌐 Bloc 1 — PCAP Analysis

### Survol initial

Avant toute question, un survol du PCAP pour cartographier le trafic.

```powershell
capinfos capture.pcapng
tshark -r capture.pcapng -q -z io,phs
```

![Liste des artefacts](screenshots/01-artefacts-ls.png)
![capinfos](screenshots/02-capinfos.png)

**Hiérarchie des protocoles :** TCP dominant, présence de HTTP, SMB2, DNS, et surtout un **volume important de `data` TCP brut** — indice d'un canal de reverse shell.

![Protocol Hierarchy](screenshots/03-protocol-hierarchy.png)

---

### Q1 — IP à l'origine de la reconnaissance

**Méthode :** un scan de ports se traduit par une IP ouvrant un très grand nombre de connexions TCP vers des ports variés.

`Statistics → Conversations → IPv4` : une paire d'IP écrase toutes les autres en nombre de paquets.

![Menu Conversations](screenshots/04-stats-conversations-menu.png)
![Conversations IPv4](screenshots/05-conversations-ipv4.png)

Confirmation via `Statistics → Endpoints` : l'IP attaquante domine en **Tx Packets** (paquets émis).

![Menu Endpoints](screenshots/06-stats-endpoints-menu.png)
![Endpoints Tx Packets](screenshots/07-endpoints-tx-packets.png)

> 🎯 ATT&CK : **T1046 – Network Service Discovery**

---

### Q2 — Outil d'énumération HTTP

**Méthode :** les outils d'énumération signent dans le `User-Agent`. Filtre `http.request`, puis clic droit sur le champ User-Agent → *Apply as Column* pour révéler le motif sur toutes les requêtes.

![Apply as Column](screenshots/08-http-useragent-apply-column.png)

Un User-Agent d'outil offensif apparaît, avec un motif de brute-force de répertoires (`/robots.txt`, `/.git/HEAD`, `/Documents/`…).

> 💡 Les premières lignes en `Microsoft-CryptoAPI` viennent du serveur lui-même (vérifications de certificats) = bruit légitime à écarter.

![User-Agent (outil flouté)](screenshots/09-http-useragent-nmap.png)

> 🎯 ATT&CK : **T1595 – Active Scanning**

---

### Q3 — Partages SMB explorés (Tree Connect)

**Méthode :** un « Tree Connect » = ouverture d'un partage réseau. Filtre :

```
smb2.cmd == 3
```

On lit les 2 premiers Tree Connect Request de l'attaquant dans la colonne *Info* (un partage administratif caché + un partage cible).

![SMB Tree Connect](screenshots/10-smb-tree-connect.png)

Détail de session SMB (NTLMSSP_AUTH, `NetShareEnumAll`, Tree Connect) confirmant l'énumération des partages.

![Détail session SMB](screenshots/12-smb-session-detail.png)

> 🎯 ATT&CK : **T1135 – Network Share Discovery**

---

### Q4 — Fichier malveillant déposé (web-shell)

**Méthode :** créer/écrire un fichier via SMB2 = opération « Create ». Filtre :

```
smb2.cmd == 5
```

Parmi les fichiers manipulés (`srvsvc`, `<share>`, …), un fichier avec une **extension exécutable par IIS** détonne : c'est le web-shell qui donnera le RCE.

![SMB Create (web-shell flouté)](screenshots/11-smb-create-shell-aspx.png)

> 🎯 ATT&CK : **T1505.003 – Web Shell**

---

### Q5 — Port du reverse shell

**Méthode :** le web-shell fait « rappeler » le serveur vers l'attaquant (reverse shell, pour contourner le pare-feu). `Statistics → Conversations → TCP`, tri par **Bytes** : la plus grosse connexion part du serveur vers l'attaquant, sur un port « uncommon but firewall-friendly ».

![TCP conversation (port flouté)](screenshots/13-tcp-conversation-4443.png)

> 🎯 ATT&CK : **T1571 – Non-Standard Port**

---

# 🧠 Bloc 2 — Memory Dump Analysis (Volatility 3)

### Q6 — Kernel base address

Vérification que le dump est exploitable et identification du système :

```powershell
vol -f memdump.mem windows.info
```

![Volatility info start](screenshots/14-volatility-info-start.png)

Le plugin confirme un **Windows Server 2019** (build 17763, 64 bits, 4 CPU) et donne la **Kernel Base**.

![windows.info (kernel base floutée)](screenshots/15-windows-info-kernel-base.png)

---

### Q7 — Exécutable de persistance (chemin sur disque)

```powershell
vol -f memdump.mem windows.pstree
```

Un exécutable inhabituel apparaît, exécuté depuis un **emplacement de persistance** (dossier de démarrage) → il se relance à chaque boot.

![pstree (chemin flouté)](screenshots/16-pstree-updatenow-startup.png)

> 🎯 ATT&CK : **T1547.001 – Startup Folder**

---

### Q8 — Processus gérant le reverse shell + PID

Dans le pstree, l'implant a pour **parent (PPID)** le worker IIS, qui exécute aussi le web-shell — d'où le lien entre réseau et mémoire.

![pstree parent (flouté)](screenshots/17-pstree-w3wp-parent.png)

Confirmation réseau : la connexion du reverse shell est détenue par ce même processus.

```powershell
vol -f memdump.mem windows.netscan | Select-String "<port>"
```

![netscan (process/port floutés)](screenshots/18-netscan-4443-w3wp.png)

---

# 🦠 Bloc 3 — Malware Sample Analysis

### Q9 — Packer utilisé

Analyse statique des chaînes du binaire (recherche de signatures de packers connus) :

```powershell
strings updatenow.exe | Select-String -Pattern "UPX|packer|PECompact|ASPack|Themida"
```

Les noms de sections révèlent un packer très répandu.

![strings (packer flouté)](screenshots/19-strings-upx.png)

> 🎯 ATT&CK : **T1027.002 – Software Packing**

---

### Q10 — Serveur C2 (FQDN)

Les chaînes statiques (même après `upx -d` / FLOSS) ne révèlent pas le domaine (déchiffré à l'exécution). Pivot via **VirusTotal → Relations → Contacted Domains** : un seul domaine flaggé se distingue des domaines légitimes (Microsoft, Sectigo…).

![VirusTotal Relations (domaine flouté)](screenshots/20-virustotal-c2-domain.png)

> 🎯 ATT&CK : **T1071.001 – Application Layer Protocol: Web Protocols**

---

### Q11 — Famille de malware

**VirusTotal → Detection** : on identifie la famille en repérant le nom qui revient chez plusieurs éditeurs (un RAT / infostealer « commodity » très répandu — keylogging, vol d'identifiants, exfiltration).

![VirusTotal Detection (famille floutée)](screenshots/21-virustotal-agenttesla.png)

---

## 🗺️ Mapping MITRE ATT&CK

| Tactique | Technique |
|---|---|
| Discovery | T1046, T1595, T1135 |
| Persistence | T1505.003 (Web Shell), T1547.001 (Startup Folder) |
| Defense Evasion | T1027.002 (Software Packing) |
| Command & Control | T1571 (Non-Standard Port), T1071.001 (Web Protocols) |

## 🧠 Ce que j'ai appris

- **Corréler 3 sources** d'artefacts (réseau + mémoire + binaire) pour reconstruire une kill chain complète.
- Différencier le **trafic légitime** (Microsoft-CryptoAPI, certificats) du **trafic malveillant**.
- La chaîne **web-shell → reverse shell → persistance → C2**, où le worker IIS fait le lien entre réseau et mémoire.
- Utiliser **Volatility 3** (`windows.info`, `windows.pstree`, `windows.netscan`) et la **threat intel** (VirusTotal) pour l'attribution.

## 🛡️ Recommandations (Blue Team)

- Restreindre les **droits d'écriture** dans les répertoires web IIS (empêcher le dépôt de web-shells).
- **Segmenter le réseau** et bloquer les connexions sortantes non nécessaires (reverse shell).
- Surveiller le **dossier Startup** et les nouveaux services (persistance).
- Alerter sur les **User-Agent** d'outils offensifs et les scans de ports.

---

> 🔒 Réponses/flags exacts non publiés (lab actif). Le writeup complet pourra être publié une fois le lab *retired*.
