"""
===========================================================================
PrefixSpan so sliding window segmentáciou
===========================================================================

Cieľ experimentu:
    Overiť vplyv SEGMENTÁCIE na výsledky PrefixSpan. Predchádzajúce
    experimenty používali session-based segmentáciu (15-min medzera medzi
    udalosťami definuje hranicu relácie). Tento experiment nahrádza sessions
    posuvným oknom (sliding window) fixnej veľkosti.

Rozdiel oproti session-based segmentácii:
    SESSION-BASED: sekvencie majú variabilnú dĺžku (medián ~113 tokenov),
    hranice sú definované časovými medzerami. Výhoda: zachytáva logickú
    štruktúru aktivity. Nevýhoda: dlhé sessions generujú exponenciálne
    veľa patternov.

    SLIDING WINDOW: sekvencie majú fixnú dĺžku (napr. 50 tokenov),
    okná sa prekrývajú (krok < veľkosť okna). Výhoda: kontrolovaná dĺžka
    sekvencií = predvídateľný počet patternov. Nevýhoda: rozseká logické
    relácie na umelé segmenty a rovnaký riadok sa vyskytuje vo viacerých
    oknách (pri prekrývaní).

    Prekrývanie okien (overlap) má dôležitú funkciu: vzor, ktorý by inak
    prekrýval hranicu okna a nebol by detegovaný, sa zachytí v susednom okne.

Parametre (po grid searchi):
    WINDOW = 50   — dĺžka okna v počte eventov
    STEP   = 10   — krok posunu (overlap = 80 %)
    SUP    = 10 % — minimálna podpora z počtu sekvencií

    Grid search testoval kombinácie okno × krok × podpora a hľadal
    konfiguráciu s najmenším zostatkom.

Predspracovanie:
    - BEZ burst detekcie, BEZ deduplikácie (rovnako ako iteratívny experiment)
    - Len tokenizácia (Channel:Provider:EventId + exe + RemoteHost)

Vyhodnotenie:
    - Presnosť filtrácie = TN / (TN + FN)
        Podiel správne odstránených (skutočne normálnych) záznamov
        z celkového počtu odstránených.

    - Recall = TP / (TP + FN)
        Podiel zachovaných forenzne relevantných záznamov z ich celkového
        počtu v datasete.

    - F1 = 2 × Presnosť × Recall / (Presnosť + Recall)
        Harmonický priemer, slúži na celkové porovnanie experimentov.

    Kde:
    - TP = attack riadok, ktorý OSTAL
    - FN = attack riadok, ktorý bol ODSTRÁNENÝ
    - TN = normálny riadok, ktorý bol ODSTRÁNENÝ
    - FP = normálny riadok, ktorý OSTAL

Dataset:
    labele.csv — Windows Event Logy z CTF výzvy "The Stolen Szechuan Sauce"
    ~40 917 záznamov, 27 labelovaných ako útočné (Label=1)
===========================================================================
"""

import os
import time
import pandas as pd
from prefixspan import PrefixSpan

_start = time.time()

# ═══════════════════════════════════════════════════════════════════
# 1. KONFIGURÁCIA
# ═══════════════════════════════════════════════════════════════════

LABELED_CSV = "C:/Users/kiara/PycharmProjects/Bakalaris/data/labele.csv"

# Sliding window parametre (výsledok grid searchu)
WINDOW   = 50    # Dĺžka okna (počet eventov)
STEP     = 5    # Krok posunu (overlap = 80 %)
SUP_PCT  = 0.10  # Minimálna podpora (10 % z počtu sekvencií)

# ── Grid search (voliteľný) ──────────────────────────────────────
# Ak GRID_SEARCH = True, prehľadá priestor parametrov a vypíše
# rebríček konfigurácií zoradených podľa veľkosti zostatku.
GRID_SEARCH    = False
TIMEOUT_SECS   = 20

GRID_WINDOWS   = [20, 30, 50, 75, 100]
GRID_STEPS     = [5, 10, 20, 30, 50]
GRID_SUP_PCTS  = [0.10, 0.15, 0.20]

# ═══════════════════════════════════════════════════════════════════
# 2. NAČÍTANIE A TOKENIZÁCIA (bez predspracovania)
# ═══════════════════════════════════════════════════════════════════

df = pd.read_csv(LABELED_CSV, sep=';')
df["TimeCreated"] = pd.to_datetime(df["TimeCreated"], errors="coerce")
print(f"Načítané riadky: {len(df)}")

df["token"] = (
    df["Channel"].astype(str) + ":" +
    df["Provider"].astype(str) + ":" +
    df["EventId"].astype(str)
)
exe_base = df["ExecutableInfo"].fillna("").apply(
    lambda x: os.path.basename(str(x)) if x else ""
)
df.loc[exe_base != "", "token"] += "|exe=" + exe_base[exe_base != ""]

mask_rh = df["RemoteHost"].notna()
rh_ip = df["RemoteHost"].astype(str).str.replace(
    r"^\[?([0-9a-fA-F\.:]+)\]?:?.*$", r"\1", regex=True
)
df.loc[mask_rh, "token"] += "|rh=" + rh_ip[mask_rh]

df["user"] = df["UserId"].fillna(df.get("UserName", pd.NA)).fillna("UNKNOWN")
df = df.sort_values(
    ["Computer", "user", "TimeCreated", "EventRecordId"]
).reset_index(drop=True)

attack_rows = set(df[df["Label"] == 1].index)
normal_rows = set(df.index) - attack_rows
print(f"Attack riadkov    : {len(attack_rows)}")
print(f"Unikátnych tokenov: {df['token'].nunique()}")

# ═══════════════════════════════════════════════════════════════════
# 3. POMOCNÉ FUNKCIE
# ═══════════════════════════════════════════════════════════════════

def build_sliding_seqs(dataframe, window, step):
    """Zostaví sekvencie pomocou sliding window.

    Okno sa posúva po skupinách Computer+user (zoradených podľa času).
    Každá sekvencia = zoznam (token, pôvodný_index) dĺžky ≤ window.
    Prekrývanie okien (overlap = window - step) zabezpečuje, že vzory
    prekrývajúce hranicu okna sú zachytené v susednom okne.
    """
    seqs = []
    for _, grp in dataframe.groupby(["Computer", "user"]):
        idxs = list(grp.index)
        toks = list(grp["token"])
        for start in range(0, max(1, len(idxs) - window + 1), step):
            s = list(zip(
                toks[start:start + window],
                idxs[start:start + window]
            ))
            if len(s) >= 2:
                seqs.append(s)
    return seqs


def get_covered(patterns, seqs):
    """Vráti množinu pôvodných indexov riadkov pokrytých
    aspoň jedným frequent patternom (subsequence matching)."""
    seq_token_sets = [set(tok for tok, _ in s) for s in seqs]
    covered = set()

    def match(pat, seq):
        res = []; pi = 0
        for tok, idx in seq:
            if pi < len(pat) and tok == pat[pi]:
                res.append(idx); pi += 1
        return res if pi == len(pat) else []

    for sup, pat in patterns:
        pat_set = set(pat)
        for i, seq in enumerate(seqs):
            if not pat_set.issubset(seq_token_sets[i]):
                continue
            covered.update(match(pat, seq))
    return covered


def run_prefixspan(seqs, sup_abs):
    """Spustí PrefixSpan a vráti frekventované vzory."""
    tokens_only = [[tok for tok, _ in s] for s in seqs]
    ps = PrefixSpan(tokens_only)
    ps.minlen = 2
    ps.maxlen = 8
    return ps.frequent(sup_abs)

# ═══════════════════════════════════════════════════════════════════
# 4. GRID SEARCH (voliteľný)
# ═══════════════════════════════════════════════════════════════════
# Prehľadáva kombinácie (window, step, support) a hľadá konfiguráciu
# s najmenším zostatkom.
# Po nájdení optimálnych parametrov sa grid search vypne
# a parametre sa nastavia v sekcii 1.

if GRID_SEARCH:
    print("\n" + "═" * 72)
    print("GRID SEARCH — prehľadávanie parametrov sliding window")
    print("═" * 72)
    print(f"  {'okno':>5} {'krok':>5} {'sup%':>5} {'#seqs':>7} {'sup_abs':>7} "
          f"{'pats':>7} {'zostatok':>9} {'atk':>4} {'rec':>8} {'presn':>8} {'čas':>6}")
    print("  " + "-" * 74)

    grid_results = []
    for w in GRID_WINDOWS:
        for step in GRID_STEPS:
            if step >= w:
                continue
            seqs = build_sliding_seqs(df, window=w, step=step)
            toks = [[tok for tok, _ in s] for s in seqs]
            for pct in GRID_SUP_PCTS:
                sup_abs = max(2, int(pct * len(seqs)))
                t0 = time.time()
                ps = PrefixSpan(toks); ps.minlen = 2; ps.maxlen = 8
                pats = ps.frequent(sup_abs)
                elapsed = time.time() - t0
                if elapsed > TIMEOUT_SECS:
                    print(f"  {w:>5} {step:>5} {int(pct*100):>4}%  TIMEOUT ({elapsed:.0f}s)")
                    break
                cov    = get_covered(pats, seqs)
                remain = set(df.index) - cov
                TP = len(attack_rows & remain)
                FN = len(attack_rows & cov)
                TN = len(normal_rows & cov)
                presn = TN / max(TN + FN, 1)
                rec = TP / max(TP + FN, 1)
                grid_results.append({
                    "w": w, "step": step, "pct": pct,
                    "seqs": len(seqs), "sup": sup_abs,
                    "pats": len(pats), "remain": len(remain),
                    "TP": TP, "FN": FN, "rec": rec, "presn": presn, "t": elapsed
                })
                print(f"  {w:>5} {step:>5} {int(pct*100):>4}% {len(seqs):>7} {sup_abs:>7} "
                      f"{len(pats):>7} {len(remain):>9} {TP:>4} "
                      f"{rec:>7.2%} {presn:>7.2%} {elapsed:>5.1f}s")

    # Rebríček: konfigurácie
    full_recall = [r for r in grid_results if r["TP"] == len(attack_rows)]
    full_recall.sort(key=lambda x: x["remain"])
    print(f"\n{'═'*72}")
    print("TOP konfigurácie s Recall = 100 %")
    print(f"{'═'*72}")
    for r in full_recall[:15]:
        print(f"  w={r['w']:>3} step={r['step']:>3} sup={int(r['pct']*100):>3}% "
              f"→ zostatok={r['remain']:>6}  ({r['remain']/len(df):.1%})")

# ═══════════════════════════════════════════════════════════════════
# 5. HLAVNÝ BEH
# ═══════════════════════════════════════════════════════════════════

print("\n" + "═" * 62)
print(f"HLAVNÝ BEH — window={WINDOW}, step={STEP}, support={int(SUP_PCT*100)}%")
print("═" * 62)

t0   = time.time()
seqs = build_sliding_seqs(df, window=WINDOW, step=STEP)
sup_abs = max(2, int(SUP_PCT * len(seqs)))

print(f"Počet sekvencií  : {len(seqs)}")
print(f"MIN_SUPPORT      : {sup_abs}  ({sup_abs/len(seqs)*100:.1f}%)")

pats    = run_prefixspan(seqs, sup_abs)
covered = get_covered(pats, seqs)

print(f"Patternov        : {len(pats)}")
print(f"Čas PrefixSpan   : {time.time()-t0:.1f}s")

# ═══════════════════════════════════════════════════════════════════
# 6. VYHODNOTENIE
# ═══════════════════════════════════════════════════════════════════

remain = set(df.index) - covered

TP = len(attack_rows & remain)
FN = len(attack_rows & covered)
FP = len(normal_rows & remain)
TN = len(normal_rows & covered)

presnost_filtracie = TN / max(TN + FN, 1)
recall             = TP / max(TP + FN, 1)
f1                 = 2 * presnost_filtracie * recall / max(presnost_filtracie + recall, 1e-9)

print(f"\n{'═'*62}")
print("VÝSLEDOK")
print(f"{'═'*62}")
print(f"  Originálny dataset    : {len(df)}")
print(f"  Pokryté (odstránené)  : {len(covered)}  ({len(covered)/len(df):.1%})")
print(f"  Zostatok              : {len(remain)}  ({len(remain)/len(df):.1%})")
print(f"  Attack ZACHOVANÉ      : {TP}/{len(attack_rows)}  ({TP/max(len(attack_rows),1):.1%})")
print(f"  Attack STRATENÉ       : {FN}")

print(f"\n  Presnosť filtrácie    : {presnost_filtracie:.2%}")
print(f"  Recall                : {recall:.2%}")
print(f"  F1                    : {f1:.2%}")

print(f"\nCelkový čas: {time.time() - _start:.1f}s")