# Interview Prep — TawasolPay Cyber Risk Copilot

Questions a senior AI/software engineer would plausibly ask about this
project, organized basic → advanced, with real answers grounded in this
codebase's actual numbers, file names, and — most importantly — the actual
bugs found and fixed while building it. Generic answers ("the LLM might
hallucinate") are exactly what a good interviewer will push past; every
answer here is written to survive that follow-up question.

**How to use this**: read it once end to end, then before an interview,
skim Section 5 (Real Bugs) and Section 9 (Behavioral) again — those are
the ones that actually differentiate you, because they can't be answered
without having lived through them.

---

## 1. Project Overview (basic)

**Q: What does this project do, in one sentence?**
It turns a fintech's raw security data — 60 assets, 114 vulnerabilities, 40
threat-intel records, 20 business services — into a ranked top-5 risk
briefing, where each risk is scored deterministically, grounded in real
NIST SP 800-53 guidance retrieved live (not memorized or hardcoded), and
narrated in plain English that's been mechanically checked before it ships.

**Q: What problem is this actually solving?**
A security team has all the data they need but no time to manually
cross-reference 114 vulnerabilities against KEV status, threat-intel
campaigns, and business impact for each one. This automates that
correlation and produces something a technical manager can read and act
on immediately, not a spreadsheet they have to interpret.

**Q: Walk me through the architecture at a high level.**
Five stages, and the split is deliberate: stages 1-4 are pure deterministic
code (pandas joins, arithmetic, search), stage 5 is the only place an LLM
touches anything.
1. **Validate** — data-quality checks, surfaces planted issues instead of
   silently fixing them.
2. **Enrich** — join vulnerabilities to assets, business services, matched
   threat intel, and CISA KEV status into one flat table.
3. **Score** — likelihood × impact, purely arithmetic, picks the top 5.
4. **Retrieve** — hybrid BM25 + dense-embedding search over the real NIST
   800-53 catalog for each of the top 5.
5. **Narrate** — a bounded LangGraph agent turns the evidence + retrieved
   controls into a written card, with a regex-based fact-check before
   anything ships.

**Q: What's the tech stack, and why these choices specifically?**
Python, pandas for the structured joins, LangGraph for the agent (chosen
because the workflow is genuinely a small state machine with conditional
branches — retries, regenerations — not a simple linear chain),
sentence-transformers + ChromaDB for the dense half of retrieval, Streamlit
for the UI, and any OpenAI-compatible LLM endpoint (currently Groq, for
free-tier compliance) via a ~40-line HTTP client with no SDK dependency.
None of these are exotic choices — the interesting decisions are in how
they're wired together, not which libraries were picked.

---

## 2. Data & Scoring (basic → intermediate)

**Q: How do you decide what the top 5 risks are?**
`risk_score = likelihood × impact × 100`, computed per finding, then the
top 5 are picked with two dedup rules: one entry per asset (chained CVEs
on the same box fold into one story) and one entry per CVE (the same bug
on twin infrastructure folds into one entry listing every affected asset).

**Q: Why multiplicative, not a weighted sum of the same factors?**
Because a weighted sum lets severity "buy back" rank regardless of
context — a CVSS-10 finding on an unreachable internal dev box could still
outscore a CVSS-8 finding on an exposed, actively-exploited production
gateway if you just add enough severity points. Multiplicative structure
makes that impossible by construction: if reachability (likelihood) is
near zero, the product is near zero no matter how severe the CVE is. This
isn't a hunch — `run_stage3.py` has sanity tests (T1, T2) asserting exactly
this ordering on real rows in the dataset, and they pass.

**Q: Walk me through the likelihood formula.**
Six multiplied factors: base exposure (internet vs internal), an
exploitation-evidence tier (KEV+ransomware > KEV alone > PoC-only >
nothing), a CVSS multiplier deliberately dampened to a tiebreaker
(`0.6 + 0.4 × cvss/10`, so CVSS alone can swing the result by at most 40%),
and three small bonus multipliers for no-auth-required, actor-targeting,
and missing EDR. The result is normalized against the true mathematical
ceiling of that formula (more on why in Section 5), not a flat 1.0.

**Q: Walk me through the impact formula.**
A weighted blend of six components (asset criticality, service revenue
impact, compliance scope, customer-facing status, RTO urgency, data
classification — weights sum to 1.0), plus two additive bonuses (a
capped dependency-cascade bonus for services other services depend on, and
a gateway-asset bonus for VPN/firewall-class devices, since compromising
one of those grants network-wide access beyond what the service's own
revenue profile implies), times an environment modifier
(Production=1.0, Staging=0.7, Dev=0.5).

**Q: A CVE in your vulnerabilities.csv has no match in the real CISA KEV
feed. Does that mean it's definitely not being exploited?**
No — and this is a real, known blind spot, not an oversight. This
dataset's synthetic CVEs (used for scenario realism) can *never* match a
real external feed like KEV by construction. That's exactly why the
"actively exploited" signal is layered: `in_kev OR ti_best_maturity in
[Weaponized, Active Exploitation, Commodity Exploit]` — the internal
`threat_intelligence.csv` feed catches most of what KEV structurally
can't. The residual gap: if a synthetic CVE is genuinely being exploited
in the scenario's fiction but neither KEV nor the internal feed has
recorded it yet, there's no signal left and the system will (correctly,
given what it knows, incorrectly given ground truth) call it "no known
exploit."

---

## 3. RAG / Retrieval (intermediate → advanced)

**Q: What did you embed, and what did you query as structured data? Why?**
Only the NIST 800-53 catalog is embedded — it's genuinely unstructured
prose where a vulnerability's own name rarely shares vocabulary with the
control's language ("Kong Gateway admin API exposed" vs "Boundary
Protection" share no words at all). Everything else — the five CSVs — is
queried directly with pandas. That data is relational: "which
vulnerabilities are on internet-exposed assets" is a join and a boolean
mask, not a similarity search, and embedding it would trade exact,
auditable answers for approximate ones on data that never needed
approximating.

**Q: Explain the hybrid retrieval design.**
Two independent search backends over the same 1,237 NIST control chunks:
BM25 (keyword/lexical — strong on NIST's exact compliance jargon like
"flaw remediation") and dense embeddings via sentence-transformers'
all-MiniLM-L6-v2 + ChromaDB (semantic — bridges vocabulary gaps keyword
search can't). Each query is ranked by both, and the rankings are fused
with Reciprocal Rank Fusion (`1/(60+rank+1)` per list, summed) rather than
picking one or the other — a control that ranks well on *both* keyword and
meaning wins, which is more robust than trusting either signal alone.

**Q: What happens if the embedding model can't load — say, no network?**
The retriever catches that failure and degrades to BM25-only, logging its
actual mode (`retriever.mode`) rather than crashing or silently pretending
hybrid search still ran. This is the same resilience pattern used
everywhere else in the codebase (KEV live feed → cached snapshot; LLM →
deterministic template) — every external dependency has a designed
fallback, not a try/except that just re-raises.

**Q: How do you chunk 1,000+ pages of NIST prose for embedding?**
Not by naive character-count splitting. A control's *statement* often has
real, NIST-authored sub-requirements (58% of controls have 2+ genuinely
separate items; AC-2 has 21) — those are preserved as real chunk
boundaries first, via a real text splitter
(`SentenceTransformersTokenTextSplitter`, tokens_per_chunk=240, matching
the embedding model's actual 256-token window) rather than a hand-rolled
slice. Falls back to a character-based splitter with the same structural
preference if the real tokenizer can't load — same resilience pattern
again.

**Q: Why not just ask the LLM which NIST control applies, since these
models have almost certainly seen the NIST catalog in training?**
Two reasons. First, the assignment's own constraint: guidance must come
from the actual document, not the model's memory, specifically so the
citation is verifiable and can't silently drift or be subtly wrong in a
way nobody can check. Second, in practice: retrieval gives you an exact
control ID and exact statement text you can mechanically verify was
actually retrieved — trusting the model's memory gives you no such
anchor, and there's no way to `verify()` a claim against nothing.

**Q: How do you handle a vulnerability name that doesn't map cleanly to
NIST vocabulary — say, something the engineers never anticipated?**
A hand-written regex map (`VULN_CLASS_VOCAB`) covers common categories
(IDOR → access-control vocabulary, session-token leaks → session
authenticity vocabulary, etc.), but by its own measurement it only
matches 21 of 96 distinct vulnerability names in this dataset — enumerating
more patterns doesn't scale to open-ended real-world naming. For anything
the hand-list misses, one cheap LLM call translates the vulnerability into
NIST vocabulary generatively instead of by lookup. It only fires when the
hand-list actually misses (confirmed via a real test case: "Remote Code
Execution in Web Framework" isn't in the hand-list, and the LLM expansion
call visibly engages only for that kind of case, not for ones the free
list already covers — saving the ~5-second round trip when it's not
needed).

---

## 4. Agent Architecture (advanced)

**Q: Walk me through the LangGraph agent, node by node.**
`build_query → retrieve → grade → (rewrite loop, ≤2×) → generate → verify
→ (regenerate, ≤1×, or fallback) → finalize`. Build_query constructs 2-3
search queries from the evidence. Retrieve runs the hybrid search. Grade
has the LLM (or a heuristic if ungrounded) judge which of the retrieved
controls are actually applicable, and whether that's enough to write from
— if not, and there's a suggested better query, it loops back to
build_query, capped at 2 rewrites. Generate writes the actual narrative
from only the graded controls. Verify is a **regex ground-truth check**,
not another LLM call — it never trusts the model's judgment about its own
output. A failure there triggers one regeneration attempt with the
specific failure fed back as feedback; if that fails too, or a template
was already the source, it falls back to a deterministic template built
from the identical evidence.

**Q: What exactly does `verify()` check, and why regex instead of asking
the LLM to self-check?**
Because a model checking its own work is exactly the failure mode you're
trying to guard against — it's biased toward finding its own claims
acceptable. `verify()` checks four things mechanically: every cited
control ID must be a subset of what was actually retrieved and graded;
every CVE mentioned must belong to this specific finding (not leak in from
a related one); any CVSS or risk-score figure mentioned must numerically
match this finding's real numbers (within a small tolerance); and any
named threat actor must actually be associated with this finding, not a
different one sharing the same MDR advisory excerpt.

**Q: What happens if there's no API key configured at all?**
Nothing crashes. `grade` uses a heuristic (retrieval eval showed top-4 BM25
results are reliable enough to accept directly), and `generate` builds the
same card from a deterministic template using the identical evidence
bundle the LLM would have used. The narrative is blander, but every fact
in it is still real, and `generation_mode: template_fallback` makes that
visible rather than pretending it's LLM-grounded.

**Q: Why LangGraph specifically, rather than a plain Python function or a
simpler chain?**
Because the control flow genuinely has cycles and bounded retries — a
rewrite loop, a regenerate loop, a fallback branch — which is what a state
machine is for. A linear chain can't express "go back to build_query up to
twice, then give up," and hand-rolling that with while-loops and counters
in plain Python would just be reimplementing what LangGraph already gives
you, with worse observability (LangGraph's compiled graph is a LangChain
`Runnable`, which is what makes every node auto-trace in LangSmith with
zero extra code).

**Q: The LLM "grades" its own retrieval — isn't that circular?**
Partially, which is why grading isn't the only safety net — it's a
*quality* gate (is this enough to write a good answer from), while
`verify()` is the *correctness* gate (did the answer actually stay
truthful to what was graded). If grading is wrong (over- or
under-inclusive), the worst case is a weaker or over-broad set of citable
controls — `verify()` still catches anything generate() cites outside that
set. The heuristic fallback (`retrieved[:4]`) exists specifically because
retrieval-eval testing showed BM25's own top-k ordering is already
reliable, so grading is an enhancement, not something the correctness
guarantee actually depends on.

---

## 5. Real Bugs Found (this is the section that actually matters)

**Q: Tell me about a real bug you found in this project — not a
hypothetical, an actual one.**
The scorer's impact formula looks up categorical CSV values — like
`data_classification` — in a config file's mapping table, and a value
that doesn't exactly string-match a config key silently falls through to
a generic default (`dict.get(value, default)`). No error, no warning. I
found it by auditing every distinct value in every relevant CSV column
against every mapping table in the config, rather than trusting that the
config was complete — and it turned out 18 of the 19 real
`data_classification` labels in the actual data (things like "Payment
Card Data") had no match in the original 5-entry map. Every payment-data
asset in the dataset was quietly being scored as generic internal data
instead of the most sensitive tier available — a real, silent
understatement of impact for exactly the asset class this tool exists to
protect. I fixed the mapping and verified the corrected scores against an
independently-written recomputation (different code path, same numbers),
but there's still no automated check that would catch the *next* one of
these if a CSV value changes without a matching config update.

**Q: Tell me about a bug that only showed up when you changed something
seemingly unrelated, like the model provider.**
When I switched the narrator LLM from OpenAI to Groq's `gpt-oss-120b` for
free-tier compliance, every single card started failing citation
verification and falling back to the template. The model hadn't stopped
citing controls — it was citing them correctly, but writing
"typographically correct" Unicode hyphens inside the citation brackets
themselves (`[SC‑23.1]` using U+2011, not the ASCII hyphen `[SC-23.1]`).
The verification regex only recognized a literal ASCII hyphen, so it read
every citation as blank and rejected perfectly valid output. I found the
exact bytes by pulling the actual failed draft out of LangSmith's trace
history and comparing it character by character against what the regex
expected — not by guessing. Fixed by normalizing hyphen variants before
matching (the displayed text is untouched; only the matching copy is
normalized), which also meant checking for and fixing the identical bug
in a second, duplicate copy of the same regex in an eval script.

**Q: Tell me about a reliability issue you found under real load.**
I ran the full 5-risk pipeline and got an alert that 4 of 5 cards had
fallen back to the template — an 80% fallback rate, on a model and prompts
I'd already individually confirmed worked. Traced it to Groq's free-tier
per-minute token limit: this particular model spends a large, variable
number of hidden "reasoning" tokens per call (confirmed via the
provider's own usage stats — 429 reasoning tokens observed on one grading
call alone), and running 5 risks back-to-back, each making several calls,
tripped the limit partway through. There was no retry logic at all, so
every call after that point failed immediately and silently degraded.
Added a bounded retry (2 attempts, honoring a `Retry-After` header when
present) specifically for 429s — not for every failure, since a genuinely
expired key or a real outage should still fail fast, not retry
pointlessly. Reran the identical pipeline afterward: 5/5 llm_grounded, no
fallback.

**Q: How do you know your fixes actually worked, versus just looking like
they worked?**
By recomputing independently, not by re-running the same code and trusting
it agreed with itself. For the scoring fix specifically, I rewrote the
entire likelihood/impact calculation from scratch in a separate script —
different join logic, different aggregation code, reading only the raw
CSVs and config directly — and confirmed it landed on the exact same
final numbers as the real pipeline. Two independently-written
implementations agreeing is real evidence; one implementation agreeing
with itself twice is not.

**Q: Describe a case where your own "safety net" was actually wrong, not
the thing it was checking.**
Exactly the Unicode-hyphen case above — the failure was never in the
model's output, it was in the verifier's assumption about what "a
citation" looks like as text. It's a useful example of a broader lesson:
a regex-based ground-truth check is only as good as its assumptions about
formatting, and those assumptions can be quietly wrong in ways that look
identical to the thing they're supposed to be catching (a hallucination)
until you actually go read the raw bytes.

---

## 6. Trade-offs & Alternatives Considered

**Q: Why Groq instead of just using OpenAI?**
The assignment requires free-tier or open-source models only. OpenAI's
API isn't free-tier; Groq's is, it's OpenAI-API-compatible (so it's a
literal drop-in — same client code, different `base_url`/`model`), and it
was already the documented "assignment-compliant" option in this repo
before I actually finished wiring it up and testing it end-to-end.

**Q: Why not fine-tune a small model instead of prompting a general one?**
Overkill for this task, and it would undermine the "guidance from the
actual NIST document" requirement — fine-tuning bakes knowledge into
weights in a way you can't cite or audit after the fact. Retrieval keeps
every fact traceable to an actual document at inference time; fine-tuning
would trade that traceability for a marginal quality gain this task
doesn't need.

**Q: Why ChromaDB and not FAISS or Pinecone?**
Local, zero-config, free, and sufficient for ~1,237 vectors — there's no
scale requirement here that would justify a managed vector DB, and FAISS
would work equally well but ChromaDB's persistence API was simpler to
wire into the existing retriever design.

**Q: You mention trying RAGAS before DeepEval for evaluation. What
happened?**
RAGAS is the more commonly cited standard, but installing it in this
project's actual environment produces a real, reproducible dependency
conflict — its import chain pulls in a `langchain_community` submodule
that no longer exists in current releases, and forcing an older
`langchain_community` back in breaks `langchain-core`'s version far enough
to conflict with LangGraph itself. This was actually installed and
reproduced, not assumed from a GitHub issue. DeepEval installs cleanly
alongside the real dependencies here and its `FaithfulnessMetric` covers
the same ground.

**Q: Why does the scoring config normalize against a computed theoretical
maximum instead of just capping each factor at 1.0?**
Because the flat cap was actively wrong, not just inelegant. Likelihood is
a chain of six multipliers, several of which sit above 1.0 as bonuses
(no-auth, actor-targeted, no-EDR) — a merely-severe finding can push the
raw product past 1.0 well before the true worst case. Capping at a flat
1.0 throws away exactly how far past that point a finding was, which can
invert the ranking between two findings that both cross 1.0 by different
margins. I found this for real: two findings in this dataset both read as
a flat `1.0` under the old scheme despite one's uncapped evidence being
clearly stronger (1.353 vs 1.113, verified by reconstructing the raw
values from the stored breakdown), which meant the weaker one incorrectly
outranked the stronger one. Normalizing against the true computed ceiling
(every multiplier at its own max, calculated from the config itself, not
hand-picked) fixed the ranking without touching any actual weight.

---

## 7. Testing & Evaluation

**Q: How do you test a system with a non-deterministic LLM in the loop?**
Split into what's actually deterministic and what isn't, and test each
appropriately. The scoring/enrichment/validation layer is pure functions
over pandas — tested with plain unit tests and 98-100% coverage. The
agent's *control flow* (does a hallucination get contained, does a bounded
rewrite loop actually bound itself, does no-API-key degrade cleanly) is
tested with mocked LLMs returning scripted responses — fully deterministic,
no network, no flakiness, and it's what actually proves the architecture's
guarantees hold regardless of what a real model does. Only the *quality*
of real LLM output — is this specific prose good — needs live model calls,
and that's kept in separate, explicitly-run eval tiers rather than the
main test suite.

**Q: What's the difference between your Tier 1 and Tier 2 evaluation?**
Tier 1 (`output_quality.py`) is free, deterministic, pattern-based checks
run against real generated text — every check targets an issue actually
observed in a real trace (uncited bullets, CVSS-led openings despite the
prompt forbidding it, numbers that don't match the real CVSS/score,
mentions of the wrong threat actor), not a hypothetical failure mode.
Tier 2 (`eval_faithfulness_deepeval.py`) costs real money — an independent
LLM judge (deliberately a different model *and* a different
provider/endpoint than the generator, so nothing grades its own homework)
scores whether every claim in the narrative is actually supported by the
evidence it was given, which pattern-matching can't assess.

**Q: How do you evaluate retrieval quality specifically, separate from
generation quality?**
5 hand-picked query→expected-control pairs (the same 5 controls the
assignment itself names as most relevant) checked against real retrieval
output before any LLM touches it — this isolates "does the search
mechanism work" from "does the model write well," which matters because a
bad narrative built on good retrieval is a prompting problem, but a good
narrative built on bad retrieval is a much harder problem to notice. If I
had to name the single biggest gap in this project, it's that this eval
only covers 5 of 96 distinct vulnerability names in the dataset — that's
where I'd actually put more time.

**Q: What is LangSmith tracing giving you here, concretely?**
Since the compiled LangGraph agent is a LangChain `Runnable`, every node
(build_query, retrieve, grade, generate, verify) auto-traces with zero
code changes once `LANGSMITH_TRACING=true` is set — the only thing that
needed an explicit `@traceable` decorator was the raw LLM HTTP call
itself, since that's not a LangChain object. In practice this is what let
me pull the exact failing draft bytes for the Unicode-hyphen bug instead
of trying to reproduce a non-deterministic model failure blind.

---

## 8. Production Readiness / Scaling

**Q: What's missing between this and a real production system?**
In priority order: authentication (the app currently has none — anyone
with the URL sees real vulnerability and business-impact data), a real
secrets manager (currently `.env` + a sidebar text box), a real database
(source of truth is flat CSVs + a local ChromaDB SQLite file, no
concurrent-write safety, no backup/DR story), rate limiting and proper
retry/backoff on every external call (only the LLM call has this now,
added reactively after hitting it — `kev.py` and `nist_catalog.py`'s HTTP
calls still don't), and an API layer, since right now nothing but
Streamlit can consume this programmatically.

**Q: How would you scale this to handle many concurrent users?**
The five independent risk narrations are currently processed serially in
a plain for-loop, each one blocking on network I/O — an easy,
safe parallelization (thread pool or async) that's currently left on the
table. Beyond that, Streamlit's single-process-per-session model doesn't
horizontally scale the way a stateless API + separate frontend would; that
split would be the actual architectural change needed, not a tuning knob.

**Q: What security concerns would you flag about the current design?**
The generate step sends exact vendor/version strings and internal
infrastructure details to a third-party LLM API — fine for this synthetic
dataset, but for a real fintech's real data, "we're sending precise
exploit-relevant details about our payment systems to an external API" is
exactly the kind of thing that needs an explicit, signed-off data-handling
decision, not something to discover after the fact.

---

## 9. Behavioral / Judgment

**Q: If you had one more day, what's the single most important thing
you'd improve, and why?**
Real retry/backoff across every LLM call, not just the rate-limit case I
already fixed. I watched the narrow fix work — 429 specifically, a clear
error, a `Retry-After` header — but that was the easy version of the
problem. A slow response, a network blip, or any other transient failure
still gets treated identically to "give up immediately" everywhere else,
which isn't robust enough to leave running unattended.

**Q: Tell me about a time your first instinct on a fix was wrong, or
incomplete.**
When a score first showed exactly `100.0`, my first instinct was "that's
just a rounding coincidence, not interesting." Digging into *why* it hit
exactly the ceiling revealed the actual bug — the flat per-factor cap was
losing information and could invert rankings between two findings that
both saturated by different margins. The surface symptom (a suspiciously
round number) and the actual defect (lost ranking information) turned out
to be two different-sized problems bundled together, and I initially
explained them as one thing before separating them clearly for the person
I was working with.

**Q: How do you decide what's worth testing versus not, given limited
time?**
Test the things whose failure would be silent and expensive, not just the
things that are easy to test. The `data_classification` bug is the
clearest example — it never crashed, never logged an error, just quietly
produced a wrong number for the exact asset class the tool exists to
protect. That's a worse bug than a crash, because nobody would ever
notice it without deliberately auditing for it, which is why I'd rather
spend an hour cross-checking every config mapping against real data than
writing another unit test for a code path that already fails loudly when
it's wrong.

**Q: What was the most surprising thing you learned building this?**
That a completely correct, well-cited, factually grounded LLM output can
still get thrown away by your own safety net over something as trivial as
which Unicode character a model uses for a hyphen. It reframed how I think
about "hallucination containment" — the containment logic itself is a
piece of software with its own bugs and its own assumptions, not a neutral
referee, and it needs the same scrutiny as the thing it's checking.
