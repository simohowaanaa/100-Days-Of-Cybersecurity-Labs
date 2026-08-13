# 100 Days of Cybersecurity Labs

Je me suis lancé un défi simple sur le papier, exigeant au quotidien : résoudre **un lab de cybersécurité par jour pendant 100 jours**, et rédiger à chaque fois un writeup clair — assez détaillé pour qu'une autre personne puisse refaire la démarche, assez honnête pour que je puisse y revenir dans six mois et comprendre ce que j'ai appris.

Ce dépôt est le carnet de bord de ce parcours.

---

## Pourquoi ce projet

Je suis étudiant en ingénierie cybersécurité et réseaux, et je crois qu'on n'apprend vraiment qu'en mettant les mains dans les artefacts : lire un vrai PCAP, déobfusquer un vrai script, suivre une intrusion du premier paquet jusqu'au malware. La théorie donne le vocabulaire ; les labs donnent le réflexe.

L'objectif n'est pas d'accumuler des flags, mais de construire une **méthode** reproductible et de savoir l'**expliquer**. Chaque writeup suit donc la même logique : observer, identifier, corréler, puis relier les découvertes au framework MITRE ATT&CK et proposer des pistes de défense.

**Domaines couverts :** Network Forensics · SOC · Threat Intelligence · Web Security · Reverse Engineering.

---

## Progression

`██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░`  **2 / 100**

| Jour | Lab | Plateforme | Catégorie | Writeup |
|:----:|:----|:----------:|:----------|:-------:|
| 001 | Lockdown Lab | CyberDefenders | Network Forensics | [Lire](./Day-001/) |
| 002 | XLMRat Lab | CyberDefenders | Network Forensics | [Lire](./Day-002/) |

*Tableau mis à jour à chaque nouveau lab.*

---

## Comment je travaille

Chaque jour suit à peu près le même fil :

1. **Survol** de l'artefact avant toute chose — comprendre le terrain avant de chercher une réponse.
2. **Analyse** guidée par les questions, mais sans perdre de vue l'histoire globale de l'attaque.
3. **Corrélation** des sources quand il y en a plusieurs (réseau, mémoire, binaire).
4. **Rédaction** du writeup : démarche, commandes, captures, puis mapping ATT&CK et recommandations défensives.

Les outils reviennent souvent : Wireshark et tshark pour le réseau, Volatility 3 pour la mémoire, CyberChef et FLOSS pour le malware, VirusTotal pour le renseignement. Côté plateformes, je puise dans CyberDefenders, TryHackMe, Hack The Box, SecDojo et PortSwigger.

---

## Organisation du dépôt

```
.
├── Day-001/
│   ├── README.md        writeup du jour
│   └── screenshots/     captures à l'appui
├── Day-002/
├── _templates/          modèle de writeup réutilisé chaque jour
└── new-day.ps1          crée le dossier du jour à partir du modèle
```

Pour démarrer une nouvelle journée :

```powershell
.\new-day.ps1 -Day 3
```

---

## Une note sur l'éthique

Ces writeups sont publiés pour apprendre et partager, pas pour distribuer des solutions. Je respecte les conditions de chaque plateforme : tant qu'un lab est **actif**, je ne documente que la méthode — les filtres, les outils, le raisonnement — sans révéler les réponses. Les writeups complets ne concernent que les labs **retirés**, pour lesquels la publication est autorisée.

---

*Suivi quotidien du challenge sur LinkedIn. Si le parcours vous parle, n'hésitez pas à passer voir les writeups.*
