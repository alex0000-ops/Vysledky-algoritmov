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
├── GSP/
│   ├── gsp.py
│ 
├── SPADE/
│   ├── spade.py
│   
├── data/
│   └── README.md                        # Popis datasetu 
│ 
└── README.md                            # Tento súbor
```

## Prehľad experimentov

| # | Algoritmus | Presnosť filtrácie | Recall | F1 | Čas behu | Odstránených riadkov |
|---|-----------|--------------------:|-------:|---:|---------:|---------------------:|
| 1 | PrefixSpan s predprípravou | – | – | – | – | – |
| 2 | PrefixSpan 3x | – | – | – | – | – |
| 3 | PrefixSpan sliding window | – | – | – | – | – |
| 4 | GSP | – | – | – | – | – |
| 5 | SPADE | – | – | – | – | – |

### Vysvetlenie metrík

- **Presnosť filtrácie** – podiel správne odstránených (skutočne normálnych) záznamov z celkového počtu odstránených záznamov. Vyššia hodnota znamená, že pipeline omylom neodstraňuje forenzne relevantné záznamy.
- **Recall** – podiel zachovaných forenzne relevantných záznamov z ich celkového počtu v datasete. 
- **F1** – harmonický priemer presnosti filtrácie a recall, slúži na celkové porovnanie experimentov.



## Poznámka k implementácii

Implementačné časti zdrojových kódov v repozitári boli pri experimentoch generované a upravované s využitím Anthropic modelu Claude Opus 4.6. Samotná metodika experimentov, výber techník, testované prístupy a analytické rozhodnutia boli založené na vlastnej práci autora, odporúčaniach skúsenejších osôb a relevantnej literatúre.

Bakalárska práca, 2025/2026
