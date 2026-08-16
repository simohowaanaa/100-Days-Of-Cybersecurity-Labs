# Web Investigation Lab (CyberDefenders) — analyse d'une compromission web par injection SQL

*Jour 5 de mon challenge « 100 Days of Cybersecurity Labs ». Catégorie : Network Forensics. Lab retiré, donc réponses incluses.*

---

Analyste SOC chez BookWorld, une librairie en ligne, je reçois une alerte : pic anormal de requêtes en base de données. À partir d'un seul PCAP, l'objectif est de reconstituer l'attaque — vecteur d'entrée, ampleur de la fuite, et accès obtenu.

L'attaque suit une progression classique de compromission web : reconnaissance, injection SQL manuelle puis automatisée avec sqlmap, dump des bases et tables, découverte du répertoire d'administration, connexion, puis dépôt d'un web-shell.

Tout passe par HTTP. Le filtre de base est `http.request`, et beaucoup d'URL sont encodées : il faudra les décoder.

## Identifier l'attaquant

Deux IP sources apparaissent dans le trafic. `170.40.150.126` (Windows) fait des recherches légitimes (*Dracula*, *the hobbit*). `111.224.250.131` (Linux/Firefox) bascule vite sur un User-Agent **sqlmap** : c'est l'attaquant.

https://raw.githubusercontent.com/simohowaanaa/100-Days-Of-Cybersecurity-Labs/main/Day-005/screenshots/01-attacker-ip.png

**Q1 — IP de l'attaquant : `111.224.250.131`**

Une recherche de géolocalisation situe l'IP en Chine, province du Hebei.

https://raw.githubusercontent.com/simohowaanaa/100-Days-Of-Cybersecurity-Labs/main/Day-005/screenshots/02-geolocation-shijiazhuang.png

**Q2 — Ville d'origine : `Shijiazhuang`**

## L'injection SQL

Toutes les injections ciblent le paramètre `search` d'un même script : `/search.php?search=…`.

https://raw.githubusercontent.com/simohowaanaa/100-Days-Of-Cybersecurity-Labs/main/Day-005/screenshots/03-search-php.png

**Q3 — Script vulnérable : `search.php`** (MITRE ATT&CK T1190)

Avant sqlmap, l'attaquant teste manuellement. La première tentative, encodée `book%20and%201=1;%20--%20-`, se décode simplement.

https://raw.githubusercontent.com/simohowaanaa/100-Days-Of-Cybersecurity-Labs/main/Day-005/screenshots/04-first-sqli.png

**Q4 — Première SQLi (décodée) : `/search.php?search=book and 1=1; -- -`**

Une fois l'injection confirmée, sqlmap interroge `INFORMATION_SCHEMA` pour énumérer les bases via `schema_name`.

https://raw.githubusercontent.com/simohowaanaa/100-Days-Of-Cybersecurity-Labs/main/Day-005/screenshots/05-databases-query.png

**Q5 — Requête listant les bases (décodée) :**

```
/search.php?search=book' UNION ALL SELECT NULL,CONCAT(0x7178766271,JSON_ARRAYAGG(CONCAT_WS(0x7a76676a636b,schema_name)),0x7176706a71) FROM INFORMATION_SCHEMA.SCHEMATA-- -
```

En suivant le flux HTTP de la requête qui énumère les tables, la réponse du serveur renvoie `["admin", "books", "customers"]`. La table des utilisateurs du site est `customers`.

https://raw.githubusercontent.com/simohowaanaa/100-Days-Of-Cybersecurity-Labs/main/Day-005/screenshots/06-customers-table.png

**Q6 — Table des utilisateurs : `customers`**

## Accès administrateur et web-shell

Après le dump, l'attaquant lance gobuster pour énumérer les répertoires, puis se dirige vers `/admin/`.

https://raw.githubusercontent.com/simohowaanaa/100-Days-Of-Cybersecurity-Labs/main/Day-005/screenshots/07-admin-directory.png

**Q7 — Répertoire découvert : `admin`**

Le `POST /admin/login.php` contient le formulaire d'authentification en clair.

https://raw.githubusercontent.com/simohowaanaa/100-Days-Of-Cybersecurity-Labs/main/Day-005/screenshots/08-credentials.png

**Q8 — Identifiants : `admin:admin123!`** (MITRE ATT&CK T1078)

Une fois connecté, l'attaquant dépose un web-shell dans `/admin/uploads/`.

https://raw.githubusercontent.com/simohowaanaa/100-Days-Of-Cybersecurity-Labs/main/Day-005/screenshots/09-webshell-upload.png

**Q9 — Web-shell uploadé : `NVri2vhp.php`** (MITRE ATT&CK T1505.003)

## Ce que je retiens

Le fil rouge du lab, c'est la lecture des URL : les tentatives d'injection sont visibles telles quelles dans `http.request`, mais leur sens n'apparaît qu'une fois décodées. La différence entre bruit et attaque tient au User-Agent — un vrai navigateur qui cherche *Dracula*, puis `sqlmap` et `gobuster` qui trahissent l'outillage offensif. Et la donnée exfiltrée (la table `customers`) n'apparaît pas dans la requête mais dans la réponse du serveur, qu'on ne voit qu'en suivant le flux.

## Côté défense

- Requêtes paramétrées pour éliminer l'injection SQL à la racine.
- Alerter sur les User-Agent d'outils offensifs (`sqlmap`, `gobuster`).
- Restreindre l'accès à `/admin/` et interdire l'exécution de fichiers dans les répertoires d'upload.

---

*Writeup complet et code sur GitHub :* [100-Days-Of-Cybersecurity-Labs](https://github.com/simohowaanaa/100-Days-Of-Cybersecurity-Labs)

*#Cybersecurity #DFIR #NetworkForensics #SQLInjection #BlueTeam*
