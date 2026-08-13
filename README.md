<div align="center">

# 100 Days of Cybersecurity Labs

<a href="https://github.com/simohowaanaa/100-Days-Of-Cybersecurity-Labs">
  <img src="https://readme-typing-svg.demolab.com/?font=Fira+Code&size=22&pause=1000&color=4AA0D5&center=true&vCenter=true&width=560&lines=1+lab+par+jour+pendant+100+jours;Network+Forensics+%C2%B7+SOC+%C2%B7+Threat+Intel;Analyser%2C+comprendre%2C+documenter." alt="typing banner" />
</a>

<br><br>

<img src="https://progress-bar.xyz/3/?scale=100&width=420&color=4aa0d5&suffix=%20/%20100" alt="progression 3/100" />

</div>

---

Un lab de cybersécurité par jour pendant 100 jours, avec à chaque fois un writeup pour garder une trace de la démarche. Ce dépôt est mon carnet de bord.

## Sommaire

- [Pourquoi ce projet](#pourquoi-ce-projet)
- [Labs résolus](#labs-résolus)
- [Techniques MITRE ATT&CK couvertes](#techniques-mitre-attck-couvertes)
- [Méthode de travail](#méthode-de-travail)
- [Outils](#outils)
- [Structure du dépôt](#structure-du-dépôt)
- [Éthique](#éthique)

## Pourquoi ce projet

Étudiant en ingénierie cybersécurité et réseaux, je progresse surtout en pratiquant : lire un vrai PCAP, déobfusquer un script, suivre une intrusion du premier paquet jusqu'au malware. L'objectif n'est pas de collectionner des flags, mais de me construire une méthode et d'être capable de l'expliquer.

Chaque writeup suit le même fil : observer, identifier, corréler, puis relier les découvertes à MITRE ATT&CK et noter quelques pistes de défense.

Domaines : Network Forensics, SOC, Threat Intelligence, Web Security, Reverse Engineering.

## Labs résolus

| Jour | Lab | Plateforme | Catégorie | Difficulté | Points clés | Writeup |
|:----:|:----|:----------:|:----------|:----------:|:------------|:-------:|
| 001 | Lockdown Lab | CyberDefenders | Network Forensics | Easy | PCAP + mémoire + malware, web-shell, reverse shell | [Lire](./Day-001/) |
| 002 | XLMRat Lab | CyberDefenders | Network Forensics | Easy | Loader PowerShell, injection dans RegSvcs.exe, AsyncRAT | [Lire](./Day-002/) |
| 003 | DanaBot Lab | CyberDefenders | Network Forensics | Easy | JavaScript obfusqué, wscript.exe, extraction d'IOCs | [Lire](./Day-003/) |

## Techniques MITRE ATT&CK couvertes

| Tactique | Techniques rencontrées |
|---|---|
| Initial Access / Execution | T1059.001 (PowerShell), T1059.007 (JavaScript), T1204.002 (User Execution) |
| Discovery | T1046 (Network Service), T1135 (Network Share), T1595 (Active Scanning) |
| Defense Evasion | T1027 (Obfuscation), T1055 (Process Injection), T1218 (Signed Binary Proxy) |
| Persistence | T1505.003 (Web Shell), T1547.001 (Startup Folder), T1053.005 (Scheduled Task) |
| Command & Control | T1071.001 (Web Protocols), T1105 (Ingress Tool Transfer), T1571 (Non-Standard Port) |

## Méthode de travail

1. Survol de l'artefact avant tout, pour comprendre le terrain.
2. Analyse guidée par les questions, sans perdre l'histoire globale.
3. Corrélation des sources quand il y en a plusieurs (réseau, mémoire, binaire).
4. Rédaction : démarche, commandes, captures, mapping ATT&CK, recommandations.

## Outils

| Domaine | Outils |
|---|---|
| Réseau | Wireshark, tshark, capinfos |
| Mémoire | Volatility 3 |
| Malware | CyberChef, FLOSS, strings |
| Threat intel | VirusTotal, ANY.RUN |
| Web / Reverse | Burp Suite, Ghidra |

Plateformes : CyberDefenders, TryHackMe, Hack The Box, SecDojo, PortSwigger.

## Structure du dépôt

```
.
├── Day-001/
│   ├── README.md        writeup du jour
│   └── screenshots/     captures à l'appui
├── Day-002/
├── Day-003/
├── _templates/          modèle de writeup
├── new-day.ps1          crée le dossier du jour
├── .gitattributes       normalisation des fins de ligne
└── LICENSE
```

Chaque dossier `Day-XXX/` est autonome : un writeup et ses captures. Pour démarrer une nouvelle journée :

```powershell
.\new-day.ps1 -Day 4
```

## Éthique

Tant qu'un lab est actif, je ne documente que la méthode — filtres, outils, raisonnement — sans révéler les réponses, conformément aux règles des plateformes. Les writeups complets ne concernent que les labs retirés.
