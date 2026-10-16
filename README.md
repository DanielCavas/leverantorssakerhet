# Leverantörssäkerhetsbedömning

**Testa verktyget: https://leverantorssakerhet.onrender.com**

Ett webbverktyg för att göra en första bedömning av en leverantör eller ett system utifrån europeiska säkerhetskrav. Välj informationsklass (K1–K4), ange leverantörens webbadress och klicka på **Analysera**. Verktyget söker igenom leverantörens webbplats och offentliga tredjepartskällor efter tecken på att kraven uppfylls. Resultatet kan laddas ner som en PDF-rapport.

Sidan ligger på Renders gratisplan och kan behöva upp till en minut för att starta om ingen har använt den på ett tag.

## Informationsklasser

| Klass | Beskrivning | Antal krav |
|-------|-------------|-----------:|
| K1 | Offentlig / Ej känslig | 4 |
| K2 | Intern / Begränsad | 11 |
| K3 | Konfidentiell | 18 |
| K4 | Strikt konfidentiell | 20 |

Varje kravområde, till exempel kryptering eller incidenthantering, bedöms en gång. En högre informationsklass skärper kravet inom samma område istället för att lägga till ett nytt, överlappande krav. Varje område har egna sökord, så samma underlag räknas aldrig för flera krav.

## Regelverk

- NIS2 (EU 2022/2555)
- DORA (EU 2022/2554)
- ISO/IEC 27001:2022, inklusive åtgärderna i bilaga A
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
