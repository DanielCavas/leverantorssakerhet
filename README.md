# Leverantörssäkerhetsbedömning

**Testa verktyget: https://leverantorssakerhet.onrender.com**

Ett webbverktyg för att göra en första bedömning av en leverantör eller ett system utifrån europeiska säkerhetskrav. Välj informationsklass (K1–K4), ange leverantörens webbadress och klicka på **Analysera**. Verktyget söker igenom leverantörens webbplats och offentliga tredjepartskällor efter tecken på att kraven uppfylls. Resultatet kan laddas ner som en PDF-rapport.

Sidan ligger på Renders gratisplan och kan behöva upp till en minut för att starta om ingen har använt den på ett tag.

## Informationsklasser

| Klass | Beskrivning | Antal krav |
|-------|-------------|-----------:|
| K1 | Offentlig / Ej känslig | 3 |
| K2 | Intern / Begränsad | 10 |
| K3 | Konfidentiell | 23 |
| K4 | Strikt konfidentiell | 33 |

Klasserna bygger på varandra: K3 innehåller även kraven för K1 och K2.

## Regelverk

- NIS2 (EU 2022/2555)
- DORA (EU 2022/2554)
- GDPR och PCI DSS där det är relevant

## Om bedömningen

Bedömningen är automatisk och vägledande. Den ersätter inte en formell granskning, till exempel genom att begära certifikat, revisionsrapporter och avtal direkt från leverantören.

## Köra lokalt

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/uvicorn main:app --port 8000
```

Öppna sedan http://127.0.0.1:8000.
