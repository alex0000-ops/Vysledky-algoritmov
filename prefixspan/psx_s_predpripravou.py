"""
===========================================================================
PrefixSpan s predspracovaním datasetu
===========================================================================

Cieľ experimentu:
    Overiť, aký vplyv má predspracovanie Windows Event Logov na schopnosť
    algoritmu PrefixSpan identifikovať a odstrániť rutinnú (bežnú) aktivitu,
    čím sa zmenší objem dát pre forenzného analytika.

    Systém funguje ako FILTER, nie ako klasifikátor útokov:
    1. Nájde frekventované sekvenčné vzory (= bežná aktivita)
    2. Riadky pokryté týmito vzormi označí ako "bežné" a odstráni
    3. To čo ostane (reziduá) ide forenzikovi na manuálnu analýzu

Predspracovanie a jeho dôvody:
    1. TOKENIZÁCIA (Channel:Provider:EventId + voliteľne exe, RemoteHost)
       – Prevod surových logov na symbolickú reprezentáciu vhodnú pre
         sekvenčné dolovanie. Kombinácia Channel+Provider+EventId zachytáva
         sémantiku udalosti (napr. "Security:Audit:4624" = úspešné prihlásenie).
         Väčšina riadkov má tieto údaje, nie sú chýbajúce. Sú to stĺpce s najväščou výpovednou
         hodnotou. Ich kombinácia bola zvolená na základe toho, že vytvárajú dostatočne jedinečné
         tokeny aby sa aktivita útočníka dala odlíšiť od bežnej a dostatočne málo, aby malo zmysel
         hľadať vozry.

    2. SESSION SEGMENTÁCIA (15-min medzera)
       – Rozdelenie prúdu udalostí na logické relácie. Udalosti od rovnakého
         používateľa oddelené pauzou > 15 min patria do rôznych relácií.
         Max dĺžka relácie = 200 tokenov.

    3. BURST DETEKCIA (≥3 rovnaké tokeny po sebe)
       – Opakujúce sa udalosti (napr. Windows Store) sú označené príznakom
         |BURST, čím sa odlíšia od izolovaných výskytov. Pomáha PrefixSpanu
         identifikovať repetitívne vzory ako rutinnú aktivitu.

         Týmto by sa dal odhaliť úrok brute force alebo scannig, keďže tieto
         typy útokov produkujú veľa logov.

    4. DEDUPLIKÁCIA (po sebe idúce rovnaké tokeny → jeden)
       – Výrazne skracuje sekvencie (~42 % redukcia).
         DÔSLEDOK: odstraňuje aj attack riadky, ktoré sa opakujú rovnako
         ako bežná aktivita — to je merateľná strata.

Vyhodnotenie:
    Metriky sú definované z perspektívy forenzného filtra:

    - TP = attack riadok, ktorý OSTAL (forenzik ho uvidí)
    - FN = attack riadok, ktorý bol ODSTRÁNENÝ (strata dôkazu)
    - FP = normálny riadok, ktorý OSTAL (šum pre forenzika)
    - TN = normálny riadok, ktorý bol ODSTRÁNENÝ (úspešná redukcia)

    - Presnosť filtrácie = TN / (TN + FN)
        Podiel správne odstránených (skutočne normálnych) záznamov
        z celkového počtu odstránených. Vyššia hodnota = menej omylom
        odstránených forenzne relevantných záznamov.

    - Recall = TP / (TP + FN)
        Podiel zachovaných forenzne relevantných záznamov z ich celkového
        počtu. V kontexte forenznej analýzy je recall prioritná metrika —
        je lepšie analyzovať viac dát, ako premeškať útok.

    - F1 = 2 × Presnosť × Recall / (Presnosť + Recall)
        Harmonický priemer, slúži na celkové porovnanie experimentov.

Dataset:
    labele.csv — Windows Event Logy z CTF výzvy "The Stolen Szechuan Sauce"
    ~40 917 záznamov, 27 labelovaných ako útočné (Label=1)

Algoritmus:
    PrefixSpan (Pei et al., 2001) — depth-first, projection-based
    sekvenčné dolovanie vzorov.
===========================================================================
"""

import os
import pandas as pd
from prefixspan import PrefixSpan
import time

_start = time.time()

# ═══════════════════════════════════════════════════════════════════
# 1. KONFIGURÁCIA
# ═══════════════════════════════════════════════════════════════════

LABELED_CSV     = "C:/Users/kiara/PycharmProjects/Bakalaris/data/labele.csv"

# Parametre predspracovania
SESSION_GAP_MIN = 15    # Nová session po 15 min pauze
BURST_THRESHOLD = 3     # ≥3 rovnaké tokeny po sebe = burst
MAX_SESSION_LEN = 200   # Max dĺžka session v tokenoch

# ═══════════════════════════════════════════════════════════════════
# 2. NAČÍTANIE DÁT
# ═══════════════════════════════════════════════════════════════════

df = pd.read_csv(LABELED_CSV, sep=';')
df["TimeCreated"] = pd.to_datetime(df["TimeCreated"], errors="coerce")
print(f"Načítané riadky: {len(df)}")

# ═══════════════════════════════════════════════════════════════════
# 3. PREDSPRACOVANIE: tokenizácia, sessions, burst, deduplikácia
# ═══════════════════════════════════════════════════════════════════

df_f = df.copy()

# --- 3a. Tokenizácia: Channel:Provider:EventId ---
df_f["token"] = (
    df_f["Channel"].astype(str) + ":" +
    df_f["Provider"].astype(str) + ":" +
    df_f["EventId"].astype(str)
)

exe_base = df_f["ExecutableInfo"].fillna("").apply(
    lambda x: os.path.basename(str(x)) if x else ""
)
mask_exe = exe_base != ""
df_f.loc[mask_exe, "token"] += "|exe=" + exe_base[mask_exe]

mask_rh = df_f["RemoteHost"].notna()
rh_ip = df_f["RemoteHost"].astype(str).str.replace(
    r"^\[?([0-9a-fA-F\.:]+)\]?:?.*$", r"\1", regex=True
)
df_f.loc[mask_rh, "token"] += "|rh=" + rh_ip[mask_rh]

# --- 3b. Session segmentácia ---
df_f["user"] = df_f["UserId"].fillna(df_f.get("UserName", pd.NA)).fillna("UNKNOWN")
df_f = df_f.sort_values(["Computer", "user", "TimeCreated", "EventRecordId"])

gap = df_f.groupby(["Computer", "user"])["TimeCreated"].diff()
time_break = gap.isna() | (gap > pd.Timedelta(minutes=SESSION_GAP_MIN))

def assign_sessions_with_size_limit(group):
    session_id  = 0
    token_count = 0
    ids = []
    for is_new in time_break[group.index]:
        if is_new or token_count >= MAX_SESSION_LEN:
            session_id  += 1
            token_count  = 0
        token_count += 1
        ids.append(session_id)
    return pd.Series(ids, index=group.index)

df_f["session_id"] = df_f.groupby(["Computer", "user"], group_keys=False).apply(
    assign_sessions_with_size_limit
)

df_f["case_session"] = (
    df_f["Computer"].astype(str)
    + "|" + df_f["user"].astype(str)
    + "|S" + df_f["session_id"].astype(int).astype(str)
)

print(f"Celkom relácií: {df_f['case_session'].nunique()}")

# --- 3c. Burst detekcia ---
run_len = df_f.groupby("case_session")["token"].transform(
    lambda s: s.groupby((s != s.shift()).cumsum()).transform("count")
)
df_f["token"] = df_f.apply(
    lambda r: r["token"] + "|BURST" if run_len[r.name] >= BURST_THRESHOLD else r["token"],
    axis=1
)

# --- 3d. Deduplikácia ---
df_f["prev_token"] = df_f.groupby("case_session")["token"].shift(1)
df_f = df_f[df_f["token"] != df_f["prev_token"]].copy()

print(f"Riadky po deduplikácii: {len(df_f)}")

# --- 3e. Príprava sekvencií ---
seqs_indexed = (
    df_f.reset_index()
    .groupby("case_session")[["token", "index"]]
    .apply(lambda g: list(zip(g["token"], g["index"])))
)

all_lengths = seqs_indexed.apply(len)
seqs_indexed = seqs_indexed[all_lengths.between(2, 200)]

rows_in_seqs = set(idx for seq in seqs_indexed for _, idx in seq)

print(f"Riadky v sekvenciách: {len(rows_in_seqs)}")
print(f"Mimo sekvencií (out-of-scope): {len(set(df.index) - rows_in_seqs)}")

# ═══════════════════════════════════════════════════════════════════
# 4. PREFIXSPAN – dolovanie frekventovaných sekvencií
# ═══════════════════════════════════════════════════════════════════

seqs_for_ps = [[tok for tok, _ in seq] for seq in seqs_indexed]

ps        = PrefixSpan(seqs_for_ps)
ps.minlen = 2   # Minimálna dĺžka vzoru
ps.maxlen = 8   # Maximálna dĺžka vzoru

MIN_SUPPORT = 20
print(f"MIN_SUPPORT: {MIN_SUPPORT}  (z {len(seqs_for_ps)} relácií)")

all_patterns = ps.frequent(MIN_SUPPORT)
all_patterns = sorted(all_patterns, key=lambda x: (x[0], len(x[1])), reverse=True)

print(f"Nájdených vzorov: {len(all_patterns)}")

# ═══════════════════════════════════════════════════════════════════
# 5. PATTERN COVERAGE – označenie riadkov pokrytých vzormi
# ═══════════════════════════════════════════════════════════════════
# Pre každý nájdený vzor sa hľadá jeho výskyt v sekvenciách.
# Riadky matchnuté vzorom = "bežná aktivita" → budú odstránené.
# Riadky bez pokrytia = reziduá → zostávajú pre forenzika.

def find_pattern_match_indices(pat, seq):
    """Nájde indexy riadkov v sekvencii, ktoré matchujú vzor (zachováva poradie)."""
    matched = []
    pat_idx = 0
    for tok, orig_idx in seq:
        if pat_idx < len(pat) and tok == pat[pat_idx]:
            matched.append(orig_idx)
            pat_idx += 1
    if pat_idx == len(pat):
        return matched
    return []

seq_token_sets = [set(tok for tok, _ in seq) for seq in seqs_indexed]

covered_rows = set()
seqs_list = list(seqs_indexed)

for sup, pat in all_patterns:
    pat_set = set(pat)
    for i, seq in enumerate(seqs_list):
        if not pat_set.issubset(seq_token_sets[i]):
            continue
        match_idxs = find_pattern_match_indices(pat, seq)
        covered_rows.update(match_idxs)

# ═══════════════════════════════════════════════════════════════════
# 6. VYHODNOTENIE
# ═══════════════════════════════════════════════════════════════════

attack_rows = set(df[df["Label"] == 1].index)
normal_rows = set(df.index) - attack_rows

# Tri neprekrývajúce sa vrstvy odstránenia
survived_dedup         = set(df_f.index)
removed_layer1_dedup   = set(df.index) - survived_dedup
removed_layer2_scope   = survived_dedup - rows_in_seqs
removed_layer3_pattern = covered_rows

total_removed = removed_layer1_dedup | removed_layer2_scope | removed_layer3_pattern
total_kept    = set(df.index) - total_removed

assert len(removed_layer1_dedup) + len(removed_layer2_scope) \
     + len(removed_layer3_pattern) + len(total_kept) == len(df), \
    "Vrstvy sa prekrývajú alebo chýbajú riadky!"

# --- ÚLOHA 1: Redukcia datasetu ---
print("\n" + "═" * 60)
print("ÚLOHA 1 – REDUKCIA DATASETU")
print("═" * 60)
print(f"  Originálny dataset    : {len(df)}")
print(f"  1) Deduplikácia       : −{len(removed_layer1_dedup)}  ({len(removed_layer1_dedup)/len(df):.1%})")
print(f"  2) Out-of-scope       : −{len(removed_layer2_scope)}  ({len(removed_layer2_scope)/len(df):.1%})")
print(f"  3) Frequent patterns  : −{len(removed_layer3_pattern)}  ({len(removed_layer3_pattern)/len(df):.1%})")
print(f"  Celkom odstránené     : {len(total_removed)}  ({len(total_removed)/len(df):.1%})")
print(f"  Ostáva na analýzu     : {len(total_kept)}  ({len(total_kept)/len(df):.1%})")

# --- ÚLOHA 2: Kvalita filtrácie ---
attack_kept    = attack_rows & total_kept
attack_removed = attack_rows & total_removed
normal_kept    = normal_rows & total_kept
normal_removed = normal_rows & total_removed

attack_lost_dedup   = attack_rows & removed_layer1_dedup
attack_lost_scope   = attack_rows & removed_layer2_scope
attack_lost_pattern = attack_rows & removed_layer3_pattern

TP = len(attack_kept)       # Attack OSTAL
FN = len(attack_removed)    # Attack ODSTRÁNENÝ
FP = len(normal_kept)       # Normálny OSTAL
TN = len(normal_removed)    # Normálny ODSTRÁNENÝ

# Presnosť filtrácie = TN / (TN + FN)
# Z odstránených záznamov, koľko bolo skutočne normálnych.
presnost_filtracie = TN / max(TN + FN, 1)

# Recall = TP / (TP + FN)
# Koľko attack záznamov prežilo filtráciu.
recall = TP / max(TP + FN, 1)

# F1 = harmonický priemer presnosti filtrácie a recall
f1 = 2 * presnost_filtracie * recall / max(presnost_filtracie + recall, 1e-9)

print("\n" + "═" * 60)
print("ÚLOHA 2 – KVALITA FILTRÁCIE")
print("═" * 60)
print(f"  Attack celkom         : {len(attack_rows)}")
print(f"  Attack ZACHOVANÉ      : {TP}  ({TP/max(len(attack_rows),1):.1%})")
print(f"  Attack STRATENÉ       : {FN}  ({FN/max(len(attack_rows),1):.1%})")
print(f"    − deduplikáciou     : {len(attack_lost_dedup)}")
print(f"    − out-of-scope      : {len(attack_lost_scope)}")
print(f"    − frequent patterns : {len(attack_lost_pattern)}")
print(f"\n  Presnosť filtrácie    : {presnost_filtracie:.2%}")
print(f"  Recall                : {recall:.2%}")
print(f"  F1                    : {f1:.2%}")

# --- Post-dedup metriky (izoluje vplyv samotného PrefixSpan) ---
attack_in_dedup  = attack_rows & survived_dedup
normal_in_dedup  = normal_rows & survived_dedup

TP2 = len(attack_in_dedup & total_kept)
FN2 = len(attack_in_dedup & total_removed)
FP2 = len(normal_in_dedup & total_kept)
TN2 = len(normal_in_dedup & total_removed)

presnost2 = TN2 / max(TN2 + FN2, 1)
recall2   = TP2 / max(TP2 + FN2, 1)
f12       = 2 * presnost2 * recall2 / max(presnost2 + recall2, 1e-9)

print(f"\n  Post-dedup ({len(survived_dedup)} riadkov):")
print(f"  Presnosť filtrácie    : {presnost2:.2%}")
print(f"  Recall                : {recall2:.2%}")
print(f"  F1                    : {f12:.2%}")

print(f"\nČas behu: {time.time() - _start:.1f} s")