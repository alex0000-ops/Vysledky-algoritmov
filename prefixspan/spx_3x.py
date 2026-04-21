"""
===========================================================================
Iteratívny PrefixSpan BEZ predspracovania
===========================================================================

Cieľ experimentu:
    Overiť, aký je vplyv ODSTRÁNENIA predspracovania (burst detekcia,
    deduplikácia) na výsledky PrefixSpan pipeline. V predchádzajúcom
    experimente deduplikácia odstránila 42 % riadkov, ale zároveň stratila
    11 z 27 attack riadkov (~41 %). Tento experiment beží priamo nad
    surovými tokenizovanými dátami bez akejkoľvek redukcie pred algoritmom.

    Druhá zmena: namiesto jedného prechodu sa používa ITERATÍVNY prístup
    s klesajúcou minimálnou podporou. Každý ďalší prechod beží nad
    zmenšeným datasetom (riadky pokryté v predchádzajúcich prechodoch
    sú odstránené). To umožňuje zachytiť slabšie vzory, ktoré by
    pri globálnom prehľade nedosiahli dostatočnú podporu.

Rozdiely oproti predchádzajúcemu experimentu:
    - BEZ burst detekcie (žiadne |BURST príznaky)
    - BEZ deduplikácie (po sebe idúce rovnaké tokeny OSTÁVAJÚ)
    - ITERATÍVNE prechody (10% → 5% → 2% podpora)
    - Každý prechod beží nad zostávajúcimi (ešte nepokrytými) riadkami

Motivácia iteratívneho prístupu:
    Pri jednom prechode s nízkou podporou (napr. 2 %) vzniká obrovské
    množstvo patternov (milióny), čo je výpočtovo nezvládnuteľné.
    Iteratívny prístup to rieši: prvý prechod s vysokou podporou (10 %)
    rýchlo odstráni najfrekventovanejšiu rutinu. Ďalšie prechody potom
    pracujú s menším datasetom, kde aj nízka podpora generuje zvládnuteľný
    počet patternov.

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

LABELED_CSV     = "labele.csv"
SESSION_GAP_MIN = 15
MAX_SESSION_LEN = 200

# Iteratívne prechody: klesajúca podpora
# Každý prechod beží nad riadkami, ktoré predchádzajúce prechody nepokryli.
# min_abs = záchranné absolútne minimum, ak percentuálna hodnota
# pri malom počte relácií generuje príliš veľa patternov.
PASSES = [
    {"pct": 0.10, "label": "Pas 1 – 10%"},
    {"pct": 0.05, "label": "Pas 2 –  5%"},
    {"pct": 0.02, "label": "Pas 3 –  2%", "min_abs": 8},
]

# ═══════════════════════════════════════════════════════════════════
# 2. NAČÍTANIE A TOKENIZÁCIA (bez deduplikácie, bez burst)
# ═══════════════════════════════════════════════════════════════════
# Oproti predchádzajúcemu experimentu sa preskakuje:
#   - burst detekcia (žiadne |BURST príznaky)
#   - deduplikácia (po sebe idúce rovnaké tokeny ostávajú)
# Dáta idú priamo do PrefixSpan v surovej tokenizovanej forme.

df = pd.read_csv(LABELED_CSV, sep=';')
df["TimeCreated"] = pd.to_datetime(df["TimeCreated"], errors="coerce")
print(f"Načítané riadky: {len(df)}")

# Tokenizácia: Channel:Provider:EventId + voliteľne exe, RemoteHost
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

# Session segmentácia (rovnaká ako v predchádzajúcom experimente)
df["user"] = df["UserId"].fillna(df.get("UserName", pd.NA)).fillna("UNKNOWN")
df = df.sort_values(["Computer", "user", "TimeCreated", "EventRecordId"]).copy()
gap = df.groupby(["Computer", "user"])["TimeCreated"].diff()
time_break = gap.isna() | (gap > pd.Timedelta(minutes=SESSION_GAP_MIN))

def assign_sessions(group):
    sid = 0; cnt = 0; ids = []
    for is_new in time_break[group.index]:
        if is_new or cnt >= MAX_SESSION_LEN:
            sid += 1; cnt = 0
        cnt += 1; ids.append(sid)
    return pd.Series(ids, index=group.index)

df["session_id"] = df.groupby(
    ["Computer", "user"], group_keys=False
).apply(assign_sessions)

df["case_session"] = (
    df["Computer"].astype(str) + "|" +
    df["user"].astype(str) + "|S" +
    df["session_id"].astype(int).astype(str)
)

attack_rows = set(df[df["Label"] == 1].index)
normal_rows = set(df.index) - attack_rows
print(f"Relácií celkom    : {df['case_session'].nunique()}")
print(f"Attack riadkov    : {len(attack_rows)}")
print(f"Unikátnych tokenov: {df['token'].nunique()}")

# ═══════════════════════════════════════════════════════════════════
# 3. POMOCNÉ FUNKCIE
# ═══════════════════════════════════════════════════════════════════

def build_seqs(dataframe):
    """Zostaví indexované sekvencie (token, orig_index) zo zadaného dataframu.
    Vráti iba sekvencie s dĺžkou >= 2."""
    seqs = (
        dataframe.reset_index()
        .groupby("case_session")[["token", "index"]]
        .apply(lambda g: list(zip(g["token"], g["index"])))
    )
    return seqs[seqs.apply(len) >= 2]


def get_covered(patterns, seqs_list):
    """Vráti množinu pôvodných indexov riadkov pokrytých aspoň jedným patternom.
    Zachováva poradie tokenov vo vzore (subsequence matching)."""
    seq_token_sets = [set(tok for tok, _ in s) for s in seqs_list]
    covered = set()

    def match(pat, seq):
        res = []; pi = 0
        for tok, idx in seq:
            if pi < len(pat) and tok == pat[pi]:
                res.append(idx); pi += 1
        return res if pi == len(pat) else []

    for sup, pat in patterns:
        pat_set = set(pat)
        for i, seq in enumerate(seqs_list):
            if not pat_set.issubset(seq_token_sets[i]):
                continue
            covered.update(match(pat, seq))
    return covered

# ═══════════════════════════════════════════════════════════════════
# 4. ITERATÍVNY PREFIXSPAN
# ═══════════════════════════════════════════════════════════════════
# Každý prechod:
#   1. Zostaví sekvencie z aktuálne aktívnych (ešte nepokrytých) riadkov
#   2. Spustí PrefixSpan s danou minimálnou podporou
#   3. Nájde pokrytie — riadky matchnuté vzormi
#   4. Odstráni pokryté riadky z aktívneho datasetu
#   5. Ďalší prechod pracuje s menším datasetom
#
# Prvý prechod (10 %) zachytí najfrekventovanejšiu rutinu.
# Ďalšie prechody zachytávajú jemnejšie vzory, ktoré boli predtým
# maskované dominantnými vzormi.

print("\n" + "═" * 62)
print("ITERATÍVNY PREFIXSPAN  (bez predspracovania)")
print("═" * 62)

active_idx  = set(df.index)
all_covered = set()
df_active   = df.copy()

pass_log = []

for cfg in PASSES:
    t0      = time.time()
    seqs    = build_seqs(df_active)
    n_seqs  = len(seqs)

    # Podpora: percentuálna z aktuálneho počtu relácií,
    # s voliteľným absolútnym minimom proti explózii patternov
    sup_abs = max(2, int(cfg["pct"] * n_seqs))
    if "min_abs" in cfg:
        sup_abs = max(sup_abs, cfg["min_abs"])

    tokens_only = [[tok for tok, _ in s] for s in seqs]
    ps = PrefixSpan(tokens_only)
    ps.minlen = 2
    ps.maxlen = 8
    pats    = ps.frequent(sup_abs)
    covered = get_covered(pats, seqs.tolist())

    newly        = covered - all_covered
    all_covered |= newly
    active_idx  -= newly
    df_active    = df[df.index.isin(active_idx)].copy()

    atk_newly  = len(attack_rows & newly)
    atk_remain = len(attack_rows & active_idx)
    elapsed    = time.time() - t0

    log = {
        "label":      cfg["label"],
        "sup_abs":    sup_abs,
        "n_seqs":     n_seqs,
        "n_patterns": len(pats),
        "newly":      len(newly),
        "atk_newly":  atk_newly,
        "remain":     len(active_idx),
        "atk_remain": atk_remain,
        "elapsed":    elapsed,
    }
    pass_log.append(log)

    print(f"\n{cfg['label']}  |  relácií={n_seqs}, sup≥{sup_abs}")
    print(f"  Patternov nájdených  : {len(pats)}")
    print(f"  Novo pokrytých       : {len(newly)}  (attack: {atk_newly})")
    print(f"  Aktívnych zostatok   : {len(active_idx)}  (attack zostatok: {atk_remain})")
    print(f"  Čas pasu             : {elapsed:.1f}s")

# ═══════════════════════════════════════════════════════════════════
# 5. VYHODNOTENIE
# ═══════════════════════════════════════════════════════════════════

total_kept    = active_idx
total_removed = set(df.index) - active_idx

TP = len(attack_rows & total_kept)
FN = len(attack_rows & total_removed)
FP = len(normal_rows & total_kept)
TN = len(normal_rows & total_removed)

presnost_filtracie = TN / max(TN + FN, 1)
recall             = TP / max(TP + FN, 1)
f1                 = 2 * presnost_filtracie * recall / max(presnost_filtracie + recall, 1e-9)

print(f"\n{'═'*62}")
print("SÚHRN")
print(f"{'═'*62}")
print(f"  Originálny dataset    : {len(df)}")
print(f"  Celkom odstránené     : {len(total_removed)}  ({len(total_removed)/len(df):.1%})")
print(f"  Zostatok              : {len(total_kept)}  ({len(total_kept)/len(df):.1%})")
print(f"  Attack ZACHOVANÉ      : {TP}/{len(attack_rows)}  ({TP/max(len(attack_rows),1):.1%})")
print(f"  Attack STRATENÉ       : {FN}")

print(f"\n  Presnosť filtrácie    : {presnost_filtracie:.2%}")
print(f"  Recall                : {recall:.2%}")
print(f"  F1                    : {f1:.2%}")

# Porovnanie pasov
print(f"\nPorovnanie pasov:")
print(f"  {'Pas':<18} {'sup':>5}  {'patterny':>9}  {'novo':>6}  {'zostatok':>9}  {'attack':>7}")
print(f"  {'-'*18}  {'-'*5}  {'-'*9}  {'-'*6}  {'-'*9}  {'-'*7}")
for lg in pass_log:
    print(f"  {lg['label']:<18}  {lg['sup_abs']:>5}  {lg['n_patterns']:>9}  "
          f"{lg['newly']:>6}  {lg['remain']:>9}  {lg['atk_remain']:>7}")

print(f"\nCelkový čas: {time.time() - _start:.1f}s")
