# Experimentmiljö – Kandidatuppsats Datavetenskap 2026

## Mappstruktur

```
experiment/
├── .env                → API-nycklar till AI-modellerna
├── requirements.txt    → Python-beroenden
├── experiment.py       → Huvudskript – kör alla 20 testfall mot båda modellerna
├── README.md           → Denna fil
└── results/            → Skapas automatiskt vid körning
    ├── raw/            → 20 individuella kodoutputs filer (.txt)
    ├── experiment_log.json   → Komplett logg över alla API-anrop
```

---

## Steg 1: Installation

```bash
# Installera Python-beroenden
pip install -r requirements.txt

```

---

## Steg 2: API-nycklar

```bash

# Öppna .env och fyll i api nycklar:
# OPENAI_API_KEY=
# ANTHROPIC_API_KEY=
```

### Verifiera GPT-5 modellnamnet
Kontrollera det exakta modell-ID:t på:
https://platform.openai.com/docs/models

Uppdatera OPENAI_MODEL i .env om det skiljer sig från "gpt-5.5"

---

## Steg 3: Kör experimentet

```bash
python experiment.py
```

Skriptet gör följande:
- Skickar alla 20 prompts till GPT-5 och Claude Sonnet 4.6
- Kör varje prompt 3 gånger per modell (totalt 120 anrop)
- Sparar alla output av både modellerna på verje scenario som results/raw/framework.txt osv.

Estimerad körtid: 15–25 minuter (beroende på API-svarstider)
Estimerad kostnad: ~$5–15 USD totalt (beror på token-användning)

---

## Steg 5: Manuell analys och klassificering

### Majoritetsregel
Rapportera det utfall som förekommer i ≥2 av 3 körningar per modell och testfall.


## Felsökning

**"model not found" för GPT-5:**
Kontrollera modellnamnet på https://platform.openai.com/docs/models
och uppdatera OPENAI_MODEL i .env.

**Rate limit-fel:**
Öka pausen i experiment.py: `time.sleep(3)` istället för `time.sleep(1.5)`.
