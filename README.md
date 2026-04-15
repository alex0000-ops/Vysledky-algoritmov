# Výsledky algoritmov – Bakalárska práca

Repozitár obsahuje kódy a výsledky experimentov s algoritmami sekvenčného dolovania dát (Sequential Pattern Mining), ktoré boli použité v rámci bakalárskej práce zameranej na digitálnu forenznú analýzu Windows Event Logov.

## Cieľ

Cieľom pipeline je **identifikovať a odstrániť rutinnú (normálnu) aktivitu** z logov, čím sa izolujú forenzne relevantné udalosti. Algoritmy hľadajú opakujúce sa sekvenčné vzory v logovacích záznamoch – záznamy, ktoré sú pokryté týmito vzormi, sa považujú za normálnu aktivitu a sú odfiltrované.

## Dataset

Experimenty boli vykonané na datasete odvodenom z CTF forenznej výzvy *The Stolen Szechuan Sauce*, obsahujúcom ~40 917 záznamov Windows Event Logov (~27,5 % útokov).

## Štruktúra repozitára

```
├── prefixspan/
│   ├── psx_s_predpripravou.py    
│   ├── spw_sliding_window.py
│   └── spx_3x.py
├── gsp/
│   ├── gsp_experiment_1.
│   
├── data/
│   └── README.md                        # Popis datasetu 
├── results/
│   └── porovnanie_vysledkov.md          # Súhrnná tabuľka výsledkov
└── README.md                            # Tento súbor
```

## Prehľad experimentov

| # | Algoritmus | Parametre | Presnosť filtrácie | Recall | F1 | Čas behu | Odstránených riadkov |
|---|-----------|-----------|--------------------:|-------:|---:|---------:|---------------------:|
| 1 | PrefixSpan | min_sup=..., window=..., step=... | – | – | – | – | – |
| 2 | PrefixSpan | min_sup=..., window=..., step=... | – | – | – | – | – |
| 3 | GSP | min_sup=..., window=..., step=... | – | – | – | – | – |
| 4 | GSP | min_sup=..., window=..., step=... | – | – | – | – | – |

### Vysvetlenie metrík

- **Presnosť filtrácie** – podiel správne odstránených (skutočne normálnych) záznamov z celkového počtu odstránených záznamov. Vyššia hodnota znamená, že pipeline omylom neodstraňuje forenzne relevantné záznamy.
- **Recall** – podiel zachovaných forenzne relevantných záznamov z ich celkového počtu v datasete. 
- **F1** – harmonický priemer presnosti filtrácie a recall, slúži na celkové porovnanie experimentov.


## Autor

Bakalárska práca, 2025/2026
