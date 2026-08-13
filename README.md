<div align="center">

# 100 Days of Cybersecurity Labs

<a href="https://github.com/simohowaanaa/100-Days-Of-Cybersecurity-Labs">
  <img src="https://readme-typing-svg.demolab.com/?font=Fira+Code&size=22&pause=1000&color=4AA0D5&center=true&vCenter=true&width=560&lines=1+lab+par+jour+pendant+100+jours;Network+Forensics+%C2%B7+SOC+%C2%B7+Threat+Intel;Analyser%2C+comprendre%2C+documenter." alt="typing banner" />
</a>

</div>

---

Un lab de cybersécurité par jour pendant 100 jours, avec à chaque fois un writeup pour garder une trace de la démarche. Ce dépôt est mon carnet de bord.

## Pourquoi

Étudiant en ingénierie cybersécurité et réseaux, je progresse surtout en pratiquant : lire un vrai PCAP, déobfusquer un script, suivre une intrusion du premier paquet jusqu'au malware. L'idée n'est pas de collectionner des flags, mais de me construire une méthode et d'être capable de l'expliquer.

Chaque writeup suit le même fil : observer, identifier, corréler, puis relier les découvertes à MITRE ATT&CK et noter quelques pistes de défense.

Domaines : Network Forensics, SOC, Threat Intelligence, Web Security, Reverse Engineering.

## Progression

<div align="center">

<img src="https://progress-bar.xyz/2/?scale=100&width=420&color=4aa0d5&suffix=%20/%20100" alt="progression 2/100" />

</div>

| Jour | Lab | Plateforme | Catégorie | Writeup |
|:----:|:----|:----------:|:----------|:-------:|
| 001 | Lockdown Lab | CyberDefenders | Network Forensics | [Lire](./Day-001/) |
| 002 | XLMRat Lab | CyberDefenders | Network Forensics | [Lire](./Day-002/) |

## Comment je travaille

1. Survol de l'artefact avant tout, pour comprendre le terrain.
2. Analyse guidée par les questions, sans perdre l'histoire globale.
3. Corrélation des sources quand il y en a plusieurs (réseau, mémoire, binaire).
4. Rédaction : démarche, commandes, captures, mapping ATT&CK, recommandations.

Outils courants : Wireshark et tshark, Volatility 3, CyberChef, FLOSS, VirusTotal.
Plateformes : CyberDefenders, TryHackMe, Hack The Box, SecDojo, PortSwigger.

## Organisation du dépôt

```
.
├── Day-001/
│   ├── README.md        writeup du jour
│   └── screenshots/     captures à l'appui
├── Day-002/
├── _templates/          modèle de writeup
└── new-day.ps1          crée le dossier du jour
```

Nouvelle journée :

```powershell
.\new-day.ps1 -Day 3
```

## Éthique

Tant qu'un lab est actif, je ne documente que la méthode — filtres, outils, raisonnement — sans révéler les réponses, conformément aux règles des plateformes. Les writeups complets ne concernent que les labs retirés.
