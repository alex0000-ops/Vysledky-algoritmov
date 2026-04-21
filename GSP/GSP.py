"""
gsp_pipeline.py
===============
Implementácia algoritmu GSP (Generalized Sequential Patterns) na analýzu
Windows Event Logov pre účely digitálnej forenziky.

Pipeline:
  1. Načítanie a príprava dát
  2. Tvorba tokenov (EventId_Channel_Provider)
  3. Konštrukcia sekvencií pomocou kĺzavého okna
  4. GSP mining – generovanie frekventovaných sekvenčných vzorov
  5. Vyhodnotenie a vizualizácia výsledkov
  6. Analýza filtrovania rutinných udalostí

"""

# ---------------------------------------------------------------------------
# 1. IMPORTY
# ---------------------------------------------------------------------------
import time
from collections import defaultdict

import matplotlib.pyplot as plt
import pandas as pd


# ---------------------------------------------------------------------------
# 2. NAČÍTANIE A PRÍPRAVA DÁT
# ---------------------------------------------------------------------------

# Načítanie datasetu; oddeľovač stĺpcov je bodkočiarka (CSV zo slovenského Excelu)
df = pd.read_csv("C:/Users/kiara/PycharmProjects/Bakalaris/data/labele.csv",sep=';')

# Udalosti zoradíme chronologicky podľa časovej pečiatky – poriadok je
# pre sekvenčné dolovanie kľúčový
df = df.sort_values("TimeCreated").reset_index(drop=True)


# ---------------------------------------------------------------------------
# 3. TOKENIZÁCIA
# ---------------------------------------------------------------------------

# Každý riadok sa reprezentuje jedným tokenom zloženým z troch polí:
#   EventId  – identifikátor typu udalosti
#   Channel  – zdroj logu (napr. Security, System)
#   Provider – aplikácia/služba, ktorá udalosť vygenerovala
# Táto kombinácia jednoznačne identifikuje „druh" udalosti.
df["Token"] = (
    df["EventId"].astype(str)
    + "_"
    + df["Channel"].astype(str)
    + "_"
    + df["Provider"].astype(str)
)

print(f"Počet záznamov:      {len(df)}")
print(f"Unikátnych tokenov:  {df['Token'].nunique()}")


# ---------------------------------------------------------------------------
# 4. KONŠTRUKCIA SEKVENCIÍ – KĹZAVÉ OKNO
# ---------------------------------------------------------------------------

# GSP pracuje s kolekciou sekvencií. Celý log rozdelíme na
# okná pevnej dĺžky. Každé okno = jedna „transakcia" (sekvencia udalostí).
#
# WINDOW_SIZE – počet po sebe idúcich udalostí v jednom okne
# STEP        – o koľko riadkov sa okno posunie pri každej iterácii
#               (STEP < WINDOW_SIZE → okná sa prekrývajú)
WINDOW_SIZE = 20
STEP = 10

all_tokens = df["Token"].tolist()
sequences = []
for i in range(0, len(all_tokens) - WINDOW_SIZE + 1, STEP):
    sequences.append(tuple(all_tokens[i : i + WINDOW_SIZE]))

n_sequences = len(sequences)
print(f"\nWindow size: {WINDOW_SIZE}, step: {STEP}")
print(f"Vytvorených sekvencií: {n_sequences}")


# ---------------------------------------------------------------------------
# 5. POMOCNÉ FUNKCIE GSP
# ---------------------------------------------------------------------------

def is_subsequence(pattern: tuple, sequence: tuple) -> bool:
    """
    Overí, či je `pattern` podsekvenciou `sequence`.

    Využíva iterátor nad `sequence` – prvky patternu musia byť obsiahnuté
    v sekvencii v rovnakom poradí, ale nemusia byť súvislé.

    Parametre
    ---------
    pattern  : testovaný vzor (n-tica tokenov)
    sequence : okno (n-tica tokenov), v ktorom hľadáme

    Vracia
    ------
    bool – True, ak pattern je podsekvenciou sequence
    """
    it = iter(sequence)
    return all(item in it for item in pattern)


def count_support(candidates: set, sequences: list) -> dict:
    """
    Spočíta podporu (support) každého kandidátskeho vzoru.

    Support = počet sekvencií, v ktorých sa daný vzor vyskytuje
    aspoň raz ako podsekvencia.

    Parametre
    ---------
    candidates : množina kandidátnych vzorov (n-tic tokenov)
    sequences  : zoznam všetkých okien (sekvencií)

    Vracia
    ------
    dict {vzor: počet výskytov}
    """
    support = defaultdict(int)
    for seq in sequences:
        for cand in candidates:
            if is_subsequence(cand, seq):
                support[cand] += 1
    return support


def generate_candidates_k2(freq_items: list, sequences: list) -> set:
    """
    Generuje kandidátov dĺžky k=2 z frekventovaných 1-prvkových vzorov.

    Namiesto kombinácie všetkých dvojíc (kartézsky súčin) prehľadáme
    skutočné sekvencie a vyberieme len dvojice, ktoré sa v dátach naozaj
    vyskytujú. Tým sa výrazne zredukuje počet kandidátov.

    Parametre
    ---------
    freq_items : zoznam frekventovaných 1-prvkových vzorov (napr. [('T1',), ...])
    sequences  : zoznam všetkých okien

    Vracia
    ------
    set n-tíc tvaru (token_i, token_j), kde i < j v rámci nejakej sekvencie
    """
    freq_set = {p[0] for p in freq_items}
    observed = set()
    for seq in sequences:
        for i in range(len(seq)):
            for j in range(i + 1, len(seq)):
                if seq[i] in freq_set and seq[j] in freq_set:
                    observed.add((seq[i], seq[j]))
    return observed


def generate_candidates(prev_freq: set, k: int) -> set:
    """
    Generuje kandidátov dĺžky k z frekventovaných vzorov dĺžky k-1.

    Využíva apriori princíp spojenia a orezávania (join + prune):
      - Spojenie: z dvoch vzorov p a q, kde p[1:] == q[:-1], vznikne nový
        kandidát p + (q[-1],).
      - Orezanie (prune): kandidát je zamietnutý, ak niektorá jeho
        podsekvencia dĺžky k-1 nie je frekventovaná.

    Parametre
    ---------
    prev_freq : množina frekventovaných vzorov dĺžky k-1
    k         : cieľová dĺžka (nepoužíva sa priamo, slúži pre dokumentáciu)

    Vracia
    ------
    set nových kandidátnych n-tíc dĺžky k
    """
    candidates = set()
    prev_set = set(prev_freq)
    for p in prev_freq:
        for q in prev_freq:
            # Podmienka spojenia: sufix p musí byť prefixom q
            if p[1:] == q[:-1]:
                new_cand = p + (q[-1],)
                # Orezanie: všetky (k-1)-podsekvencii musia byť frekventované
                prune = False
                for i in range(len(new_cand)):
                    sub = new_cand[:i] + new_cand[i + 1 :]
                    if sub not in prev_set:
                        prune = True
                        break
                if not prune:
                    candidates.add(new_cand)
    return candidates


# ---------------------------------------------------------------------------
# 6. PARAMETRE GSP
# ---------------------------------------------------------------------------

# MIN_SUPPORT_RATIO – minimálna relatívna podpora (podiel sekvencií)
# MAX_K             – maximálna dĺžka hľadaných vzorov (ochrana pred
#                     kombinatorickou explóziou)
MIN_SUPPORT_RATIO = 0.01
MAX_K = 10

# Absolútny minimálny support (zaokrúhlený na celé číslo, min. 1)
min_support = max(1, int(MIN_SUPPORT_RATIO * n_sequences))
print(f"\nMin support: {min_support} ({MIN_SUPPORT_RATIO:.2%} z {n_sequences} sekvencií)")


# ---------------------------------------------------------------------------
# 7. GSP MINING
# ---------------------------------------------------------------------------

start_time = time.time()
freq_patterns = {}   # {k: [(vzor, support, ratio), ...]}

# --- k = 1: frekventované 1-prvkové vzory ---
# Počítame, v koľkých oknách sa každý token aspoň raz vyskytuje.
item_counts = defaultdict(int)
for seq in sequences:
    for item in set(seq):   # set() – každý token ráta max. raz na okno
        item_counts[item] += 1

freq_1 = {
    (item,): count
    for item, count in item_counts.items()
    if count >= min_support
}
freq_patterns[1] = [(p, s, s / n_sequences) for p, s in freq_1.items()]
print(f"\nk=1: {len(freq_1)} frekventovaných tokenov")

# --- k = 2: frekventované dvojice ---
cands_2 = generate_candidates_k2(list(freq_1.keys()), sequences)
print(f"k=2: generovaných {len(cands_2)} kandidátov")

support_2 = count_support(cands_2, sequences)
freq_2 = {p: s for p, s in support_2.items() if s >= min_support}
freq_patterns[2] = [(p, s, s / n_sequences) for p, s in freq_2.items()]
print(f"k=2: {len(freq_2)} frekventovaných vzorov")

# --- k >= 3: iteratívne rozširovanie ---
k = 3
prev_freq = set(freq_2.keys()) if freq_2 else set()

while prev_freq:
    if MAX_K and k > MAX_K:
        break

    candidates = generate_candidates(prev_freq, k)
    if not candidates:
        print(f"k={k}: žiadni kandidáti, koniec")
        break

    print(f"k={k}: {len(candidates)} kandidátov")
    support_k = count_support(candidates, sequences)
    freq_k = {p: s for p, s in support_k.items() if s >= min_support}

    if not freq_k:
        print(f"k={k}: žiadne frekventované vzory, koniec")
        break

    freq_patterns[k] = [(p, s, s / n_sequences) for p, s in freq_k.items()]
    print(f"k={k}: {len(freq_k)} frekventovaných vzorov")
    prev_freq = set(freq_k.keys())
    k += 1

elapsed = time.time() - start_time
total = sum(len(v) for v in freq_patterns.values())
print(f"\nGSP hotový: {total} vzorov za {elapsed:.2f}s")


# ---------------------------------------------------------------------------
# 8. EXPORT VÝSLEDKOV DO DATAFRAME
# ---------------------------------------------------------------------------

rows = []
for length, patterns in freq_patterns.items():
    for pat, sup, ratio in patterns:
        rows.append(
            {
                "length": length,
                "pattern": " -> ".join(str(x) for x in pat),
                "support": sup,
                "support_ratio": round(ratio, 4),
            }
        )

df_results = pd.DataFrame(rows)
if not df_results.empty:
    df_results = df_results.sort_values(
        ["length", "support"], ascending=[True, False]
    ).reset_index(drop=True)

print(f"\nCelkovo {len(df_results)} vzorov")


# ---------------------------------------------------------------------------
# 9. VÝPIS TOP-5 VZOROV PRE KAŽDÉ K
# ---------------------------------------------------------------------------

for k, patterns in sorted(freq_patterns.items()):
    top = sorted(patterns, key=lambda x: x[1], reverse=True)[:5]
    print(f"\n=== Top 5 vzory dĺžky {k} ===")
    for pat, sup, ratio in top:
        print(f"  {' -> '.join(str(x) for x in pat)}  (support={sup}, {ratio:.2%})")


# ---------------------------------------------------------------------------
# 10. VIZUALIZÁCIA – POČET VZOROV PODĽA DĹŽKY K
# ---------------------------------------------------------------------------

k_values = sorted(freq_patterns.keys())
counts = [len(freq_patterns[k]) for k in k_values]

plt.figure(figsize=(10, 5))
bars = plt.bar(k_values, counts, color="#4C72B0", edgecolor="white", width=0.7)

for bar, c in zip(bars, counts):
    plt.text(
        bar.get_x() + bar.get_width() / 2,
        bar.get_height() + 200,
        f"{c:,}",
        ha="center",
        va="bottom",
        fontsize=9,
    )

plt.xlabel("Dĺžka sekvencie (k)")
plt.ylabel("Počet frekventovaných vzorov")
plt.title(
    f"GSP – Počet frekventovaných vzorov podľa dĺžky k\n"
    f"(min_support = {MIN_SUPPORT_RATIO:.0%}, celkovo {total:,} vzorov, čas = {elapsed:.1f}s)"
)
plt.xticks(k_values)
plt.tight_layout()
plt.savefig("gsp_patterns_by_k.png", dpi=150)
plt.show()


# ---------------------------------------------------------------------------
# 11. ANALÝZA FILTROVANIA RUTINNÝCH TOKENOV
# ---------------------------------------------------------------------------

# Premenujeme stĺpec Label → is_attack_related a prekonvertujeme na bool.
# Riadky s hodnotou 1 = útok, 0 (alebo NaN) = bežná aktivita.
df = df.rename(columns={"Label": "is_attack_related"})
df["is_attack_related"] = df["is_attack_related"].fillna(0).astype(int).astype(bool)

print(f"\nCelkový počet riadkov:  {len(df)}")
print(f"Attack-related riadkov: {df['is_attack_related'].sum()} ({df['is_attack_related'].mean():.2%})")

# Tokeny zoradíme podľa frekvencie zostupne a vypočítame kumulatívny súčet.
# Tým identifikujeme „rutinné" tokeny, ktoré tvoria väčšinu objemu logov.
token_counts = df["Token"].value_counts()
token_df = token_counts.reset_index()
token_df.columns = ["Token", "count"]
token_df["cum_count"] = token_df["count"].cumsum()
token_df["cum_pct"] = token_df["cum_count"] / len(df)

# Pre každý token zistíme, koľko z jeho výskytov je označených ako útok
attack_per_token = df[df["is_attack_related"]].groupby("Token").size()
token_df["attack_count"] = token_df["Token"].map(attack_per_token).fillna(0).astype(int)

# Otestujeme rôzne prahy: aká je strata útočných riadkov pri odstránení
# tokenov, ktoré tvoria X % celkového objemu?
thresholds = [0.50, 0.60, 0.70, 0.75, 0.80, 0.85, 0.90]
results = []
n_attack = df["is_attack_related"].sum()

for target in thresholds:
    # Vyberieme množinu tokenov, ktoré spolu tvoria maximálne `target` % objemu
    mask = token_df["cum_pct"] <= target
    tokens_to_remove = set(token_df.loc[mask, "Token"])
    removed = df["Token"].isin(tokens_to_remove)

    results.append(
        {
            "cieľ": f"{target:.0%}",
            "tokenov": len(tokens_to_remove),
            "riadkov_odstr": removed.sum(),
            "pct_odstr": removed.sum() / len(df),
            "attack_strata": (removed & df["is_attack_related"]).sum(),
            "attack_zach_%": 1 - (removed & df["is_attack_related"]).sum() / max(n_attack, 1),
        }
    )

df_thresh = pd.DataFrame(results)
print("\n=== Dopad odstránenia rutinných tokenov ===")
print(df_thresh.to_string(index=False))

# Graf – trade-off medzi množstvom odstránených riadkov a zachovaním útočných
fig, ax = plt.subplots(figsize=(10, 5))

x = [r["pct_odstr"] * 100 for r in results]
y = [r["attack_zach_%"] * 100 for r in results]

ax.plot(x, y, "o-", color="#e74c3c", linewidth=2, markersize=8, label="zachované attack riadky")
ax.axhline(y=100, color="gray", linestyle="--", alpha=0.3)
ax.axvline(x=80, color="gray", linestyle="--", alpha=0.3, label="cieľ 80 %")

for xi, yi, lbl in zip(x, y, [r["cieľ"] for r in results]):
    ax.annotate(lbl, (xi, yi), textcoords="offset points", xytext=(0, 10), ha="center", fontsize=9)

ax.set_xlabel("Odstránených riadkov (%)")
ax.set_ylabel("Zachované attack-related riadky (%)")
ax.set_title("Trade-off: odstránenie rutiny vs. strata attack-related dát")
ax.legend()
plt.tight_layout()
plt.savefig("gsp_tradeoff.png", dpi=150)
plt.show()

# Aplikujeme filter s prahom 80 %
TARGET = 0.80
mask_80 = token_df["cum_pct"] <= TARGET
tokens_remove_80 = set(token_df.loc[mask_80, "Token"])

df_filtered = df[~df["Token"].isin(tokens_remove_80)].copy()

print(f"\n=== Výsledok bezpečného filtrovania ===")
print(f"Pôvodne:       {len(df):,} riadkov")
print(f"Po filtrovaní: {len(df_filtered):,} riadkov ({len(df_filtered) / len(df):.1%})")
print(f"Odstránených:  {len(df) - len(df_filtered):,} ({1 - len(df_filtered) / len(df):.1%})")
print(
    f"Attack zachované: {df_filtered['is_attack_related'].sum()} / {n_attack} "
    f"({df_filtered['is_attack_related'].sum() / max(n_attack, 1):.1%})"
)


# ---------------------------------------------------------------------------
# 12. VYHODNOTENIE DOPADU KAŽDÉHO K NA FILTROVANIE
# ---------------------------------------------------------------------------

def find_pattern_row_indices(pattern: tuple, all_tokens: list, window_size: int, step: int) -> set:
    """
    Nájde indexy riadkov v pôvodnom df, ktoré sú súčasťou aspoň jedného
    výskytu daného vzoru v kĺzavých oknách.

    Pre každé okno overíme, či je `pattern` jeho podsekvenciou. Ak áno,
    všetky riadky okna, ktoré prispeli k zhode (t.j. riadky matchnutých
    tokenov), pridáme do výslednej množiny indexov.

    Parametre
    ---------
    pattern     : hľadaný sekvenčný vzor (n-tica tokenov)
    all_tokens  : celý zoznam tokenov (zodpovedá riadkom df)
    window_size : veľkosť kĺzavého okna
    step        : krok posunu okna

    Vracia
    ------
    set celých čísel – indexy riadkov v df
    """
    matched_indices = set()

    for seq_start in range(0, len(all_tokens) - window_size + 1, step):
        window = all_tokens[seq_start : seq_start + window_size]

        # Greedy prechádzanie okna: hľadáme tokeny patternu v poradí
        pos = 0
        hits = []
        for j, token in enumerate(window):
            if pos < len(pattern) and token == pattern[pos]:
                hits.append(seq_start + j)
                pos += 1
        if pos == len(pattern):
            matched_indices.update(hits)

    return matched_indices


def evaluate_k_removal(freq_patterns: dict, all_tokens: list, df: pd.DataFrame,
                        window_size: int, step: int) -> list:
    """
    Pre každú hodnotu k vyhodnotí, koľko riadkov (vrátane útočných) by
    bolo pokrytých (a teda potenciálne odstránených) vzorovmi dĺžky k.

    Parametre
    ---------
    freq_patterns : výsledky GSP – {k: [(vzor, support, ratio), ...]}
    all_tokens    : celý zoznam tokenov
    df            : pôvodný DataFrame s kolumnou is_attack_related
    window_size   : veľkosť kĺzavého okna
    step          : krok posunu okna

    Vracia
    ------
    list slovníkov s metrikami pre každé k
    """
    n_total = len(df)
    n_attack = df["is_attack_related"].sum()
    results = []

    for k in sorted(freq_patterns.keys()):
        patterns_k = [pat for pat, sup, ratio in freq_patterns[k]]
        matched = set()

        for pat in patterns_k:
            idx = find_pattern_row_indices(pat, all_tokens, window_size, step)
            matched.update(idx)

        matched_attack = sum(1 for i in matched if df.iloc[i]["is_attack_related"])
        attack_remaining = n_attack - matched_attack

        results.append(
            {
                "k": k,
                "n_patterns": len(patterns_k),
                "matched_rows": len(matched),
                "matched_pct": len(matched) / n_total,
                "matched_attack": matched_attack,
                "removable_pct": len(matched) / n_total,
                "attack_after": attack_remaining,
                "attack_after_pct": attack_remaining / max(n_attack, 1),
            }
        )

        print(
            f"k={k}: {len(patterns_k)} vzorov → {len(matched):,} matchnutých riadkov "
            f"({len(matched)/n_total:.1%}), attack odstránených: {matched_attack}, "
            f"zostatok attack: {attack_remaining} ({attack_remaining/max(n_attack,1):.1%})"
        )

    return results


print("\nVyhodnocujem dopad odstránenia pre každé k...")
eval_results = evaluate_k_removal(freq_patterns, all_tokens, df, WINDOW_SIZE, STEP)

df_eval = pd.DataFrame(eval_results)
print("\n=== Súhrnná tabuľka ===")
print(df_eval.to_string(index=False))


# ---------------------------------------------------------------------------
# 13. KUMULATÍVNE FILTROVANIE – DOSIAHNUTIE CIEĽA 80 %
# ---------------------------------------------------------------------------

def cumulative_removal_80(eval_results: list, freq_patterns: dict,
                           all_tokens: list, df: pd.DataFrame,
                           window_size: int, step: int) -> pd.DataFrame:
    """
    Kumulatívne pridáva vzory podľa ich pokrytia (od najväčšieho) a zastavuje
    sa, keď celkový podiel odstránených riadkov dosiahne 80 %.

    Cieľom je odstrániť čo najviac rutinných udalostí pri zachovaní
    maximálneho možného počtu útočných riadkov.

    Parametre
    ---------
    eval_results  : výstup funkcie evaluate_k_removal
    freq_patterns : výsledky GSP
    all_tokens    : celý zoznam tokenov
    df            : pôvodný DataFrame
    window_size   : veľkosť kĺzavého okna
    step          : krok posunu okna

    Vracia
    ------
    pd.DataFrame – prefiltrovaný dataset (bez kumulatívne odstránených riadkov)
    """
    n_total = len(df)
    TARGET = 0.80

    # Zoradíme k-hodnoty zostupne podľa pokrytia – najpokrytejšie k odstraňujeme prvé
    sorted_results = sorted(eval_results, key=lambda x: x["matched_pct"], reverse=True)

    df_sorted = pd.DataFrame(sorted_results)
    df_sorted["matched_pct"] = df_sorted["matched_pct"].map("{:.2%}".format)
    df_sorted["attack_after_pct"] = df_sorted["attack_after_pct"].map("{:.2%}".format)
    df_sorted = df_sorted.drop(columns=["removable_pct"])
    print(df_sorted.to_string(index=False))

    cumulative_removed = set()

    for row in sorted_results:
        k = row["k"]
        patterns_k = [pat for pat, sup, ratio in freq_patterns[k]]
        matched = set()
        for pat in patterns_k:
            idx = find_pattern_row_indices(pat, all_tokens, window_size, step)
            matched.update(idx)

        cumulative_removed.update(matched)
        pct = len(cumulative_removed) / n_total

        print(
            f"k={k} (matched_pct={row['matched_pct']}) "
            f"→ kumulatívne odstránených: {len(cumulative_removed):,} ({pct:.2%})"
        )

        if pct >= TARGET:
            print(f"\n→ Dosiahnutý cieľ 80 % pri k={k}")
            break

    # Finálne vyhodnotenie po kumulatívnom filtrovaní
    df_filtered = df.drop(index=list(cumulative_removed)).reset_index(drop=True)
    attack_remaining = df_filtered["is_attack_related"].sum()
    n_attack = df["is_attack_related"].sum()

    print(f"\n=== Výsledok ===")
    print(f"Pôvodne:          {n_total:,} riadkov")
    print(f"Po filtrovaní:    {len(df_filtered):,} riadkov ({len(df_filtered)/n_total:.1%})")
    print(f"Odstránených:     {len(cumulative_removed):,} ({len(cumulative_removed)/n_total:.1%})")
    print(
        f"Attack zachované: {attack_remaining} / {n_attack} "
        f"({attack_remaining/max(n_attack,1):.1%})"
    )

    return df_filtered


df_filtered = cumulative_removal_80(
    eval_results, freq_patterns, all_tokens, df, WINDOW_SIZE, STEP
)