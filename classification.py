"""
Information classification model K1–K4 with security requirements
mapped to NIS2, DORA and ISO/IEC 27001:2022 (Annex A).

Each requirement area appears once in an assessment. Higher classification
levels replace the expectation of lower levels within the same area instead
of adding a second, overlapping requirement. Keywords are kept unique per
area so that one piece of evidence is not counted for several requirements.
"""

from dataclasses import dataclass, field

LEVEL_ORDER = ["K1", "K2", "K3", "K4"]


@dataclass
class Requirement:
    area: str
    description: str
    keywords: list[str] = field(default_factory=list)
    certifications: list[str] = field(default_factory=list)
    regulatory_ref: str = ""


CLASSIFICATION_LEVELS = {
    "K1": {
        "name": "Offentlig / Ej känslig",
        "description": "Information utan skyddsbehov. Obehörig åtkomst medför ingen skada.",
    },
    "K2": {
        "name": "Intern / Begränsad",
        "description": "Information avsedd för intern användning. Obehörig åtkomst kan orsaka begränsad skada.",
    },
    "K3": {
        "name": "Konfidentiell",
        "description": "Känslig information. Obehörig åtkomst kan orsaka betydande skada.",
    },
    "K4": {
        "name": "Strikt konfidentiell",
        "description": "Högst känslig information. Obehörig åtkomst kan orsaka allvarlig eller irreparabel skada.",
    },
}


def _area(name: str, **levels: dict) -> dict[str, Requirement]:
    return {level: Requirement(area=name, **spec) for level, spec in levels.items()}


REQUIREMENT_AREAS: list[dict[str, Requirement]] = [
    _area(
        "Ledningssystem och säkerhetspolicy",
        K1=dict(
            description="Det finns en publicerad policy eller beskrivning av hur informationssäkerheten hanteras.",
            keywords=["information security", "informationssäkerhet", "security policy",
                      "säkerhetspolicy", "it-policy"],
            regulatory_ref="NIS2 Art. 21(2)(a) · ISO 27001 A.5.1",
        ),
        K2=dict(
            description="Dokumenterad informationssäkerhetspolicy som bygger på riskbedömningar och "
                        "är fastställd av ledningen.",
            keywords=["information security policy", "informationssäkerhetspolicy", "security policy",
                      "säkerhetspolicy", "risk assessment", "riskbedömning", "riskanalys"],
            regulatory_ref="NIS2 Art. 21(2)(a) · DORA Art. 5–6 · ISO 27001 kap. 5–6, A.5.1",
        ),
        K3=dict(
            description="Certifierat ledningssystem för informationssäkerhet enligt ISO 27001.",
            keywords=["isms", "information security management", "ledningssystem för informationssäkerhet",
                      "iso 27001", "iso/iec 27001"],
            certifications=["ISO 27001"],
            regulatory_ref="NIS2 Art. 21(2)(a) · DORA Art. 5–6 · ISO 27001 kap. 4–10",
        ),
        K4=dict(
            description="ISO 27001-certifiering med tillägg för molntjänster (ISO 27017/27018) och "
                        "CSA STAR nivå 2 eller högre.",
            keywords=["iso 27001", "iso 27017", "iso 27018", "csa star", "cloud security alliance"],
            certifications=["ISO 27001", "ISO 27017", "ISO 27018", "CSA STAR"],
            regulatory_ref="NIS2 Art. 21(2)(a) · DORA Art. 5–6 · ISO 27001 kap. 4–10, A.5.23",
        ),
    ),
    _area(
        "Oberoende granskning",
        K3=dict(
            description="Rapport från oberoende granskning av säkerhetskontrollerna, t.ex. SOC 2 Typ II "
                        "eller ISAE 3402.",
            keywords=["soc 2", "soc2", "type ii", "isae 3402", "ssae 18", "independent audit",
                      "oberoende granskning"],
            certifications=["SOC 2", "ISAE 3402"],
            regulatory_ref="NIS2 Art. 21(2)(f) · DORA Art. 6 · ISO 27001 A.5.35",
        ),
        K4=dict(
            description="Granskningsrapporter enligt både SOC 2 Typ II och SOC 1 (eller ISAE 3402/3000) "
                        "från oberoende revisor.",
            keywords=["soc 2 type ii", "soc 1", "isae 3402", "isae 3000", "third-party audit",
                      "tredjepartsrevision"],
            certifications=["SOC 2 Type II", "SOC 1", "ISAE 3402"],
            regulatory_ref="NIS2 Art. 21(2)(f) · DORA Art. 6 · ISO 27001 A.5.35",
        ),
    ),
    _area(
        "Medvetenhet och utbildning",
        K2=dict(
            description="Personalen får regelbunden utbildning i informationssäkerhet.",
            keywords=["security awareness", "säkerhetsmedvetenhet", "security training",
                      "säkerhetsutbildning", "phishing simulation", "cyber hygiene"],
            regulatory_ref="NIS2 Art. 21(2)(g) · DORA Art. 13(6) · ISO 27001 A.6.3",
        ),
    ),
    _area(
        "Tillgångar och informationsklassning",
        K3=dict(
            description="Förteckning över informationstillgångar och klassning av information efter skyddsbehov.",
            keywords=["asset inventory", "asset management", "tillgångsförteckning",
                      "information classification", "informationsklassning", "data classification"],
            regulatory_ref="NIS2 Art. 21(2)(i) · DORA Art. 8 · ISO 27001 A.5.9, A.5.12",
        ),
    ),
    _area(
        "Åtkomstkontroll",
        K2=dict(
            description="Rollbaserad åtkomstkontroll där användare bara får de behörigheter de behöver.",
            keywords=["rbac", "role-based", "access control", "åtkomstkontroll", "behörighetsstyrning",
                      "least privilege", "minsta behörighet"],
            regulatory_ref="NIS2 Art. 21(2)(i) · DORA Art. 9(4)(c) · ISO 27001 A.5.15, A.5.18",
        ),
    ),
    _area(
        "Inloggning och autentisering",
        K2=dict(
            description="Stark lösenordspolicy och möjlighet till flerfaktorsautentisering.",
            keywords=["password policy", "lösenordspolicy", "strong password", "mfa", "multi-factor",
                      "two-factor", "tvåfaktorsautentisering"],
            regulatory_ref="NIS2 Art. 21(2)(j) · DORA Art. 9(4)(d) · ISO 27001 A.5.17, A.8.5",
        ),
        K3=dict(
            description="Flerfaktorsautentisering (MFA) är obligatorisk för alla användare.",
            keywords=["mfa", "multi-factor", "multifactor", "two-factor", "2fa", "tvåfaktor",
                      "flerfaktorsautentisering", "single sign-on"],
            regulatory_ref="NIS2 Art. 21(2)(j) · DORA Art. 9(4)(d) · ISO 27001 A.5.17, A.8.5",
        ),
        K4=dict(
            description="Nätfiskeresistent flerfaktorsautentisering med hårdvarunyckel, t.ex. FIDO2.",
            keywords=["hardware token", "hardware key", "hårdvarunyckel", "fido2", "yubikey", "passkey",
                      "webauthn", "phishing-resistant"],
            regulatory_ref="NIS2 Art. 21(2)(j) · DORA Art. 9(4)(d) · ISO 27001 A.8.5",
        ),
    ),
    _area(
        "Privilegierad åtkomst",
        K4=dict(
            description="System för privilegierad åtkomst (PAM) med sessionsloggning, tidsbegränsad "
                        "åtkomst och fyraögonsprincip.",
            keywords=["privileged access", "privilegierad åtkomst", "just-in-time", "jit access",
                      "session recording", "sessionsloggning", "4-eyes", "dual control"],
            regulatory_ref="NIS2 Art. 21(2)(i) · DORA Art. 9(4)(c) · ISO 27001 A.8.2",
        ),
    ),
    _area(
        "Kryptering",
        K1=dict(
            description="Kryptering av externa anslutningar med TLS 1.2 eller senare.",
            keywords=["tls", "ssl", "https", "encryption", "kryptering", "encrypted"],
            regulatory_ref="NIS2 Art. 21(2)(h) · ISO 27001 A.8.24",
        ),
        K2=dict(
            description="TLS 1.2 eller senare för all trafik och kryptering av lagrad data.",
            keywords=["tls", "encryption at rest", "kryptering i vila", "disk encryption",
                      "diskkryptering", "encrypted"],
            regulatory_ref="NIS2 Art. 21(2)(h) · DORA Art. 9(2) · ISO 27001 A.8.24",
        ),
        K3=dict(
            description="AES-256-kryptering av lagrad data. TLS 1.3 och ömsesidig TLS (mTLS) mellan tjänster.",
            keywords=["aes-256", "aes 256", "tls 1.3", "mtls", "mutual tls", "encryption at rest",
                      "kryptering i vila"],
            regulatory_ref="NIS2 Art. 21(2)(h) · DORA Art. 9(2) · ISO 27001 A.8.24",
        ),
        K4=dict(
            description="Samma nivå som för K3 samt end-to-end-kryptering och certifikatlåsning där det "
                        "är tillämpligt.",
            keywords=["aes-256", "tls 1.3", "mtls", "end-to-end", "certificate pinning",
                      "certifikatlåsning", "zero knowledge"],
            regulatory_ref="NIS2 Art. 21(2)(h) · DORA Art. 9(2) · ISO 27001 A.8.24",
        ),
    ),
    _area(
        "Nyckelhantering",
        K3=dict(
            description="Dedikerat system för nyckelhantering (KMS) med regelbundet nyckelbyte.",
            keywords=["kms", "key management", "nyckelhantering", "key rotation", "nyckelrotation"],
            regulatory_ref="NIS2 Art. 21(2)(h) · DORA Art. 9(2) · ISO 27001 A.8.24",
        ),
        K4=dict(
            description="Krypteringsnycklar förvaras i en hårdvarusäkerhetsmodul (HSM) och kunden kan "
                        "hantera egna nycklar.",
            keywords=["hsm", "hardware security module", "hårdvarusäkerhetsmodul", "fips 140", "byok",
                      "bring your own key", "key rotation"],
            regulatory_ref="NIS2 Art. 21(2)(h) · DORA Art. 9(2) · ISO 27001 A.8.24",
        ),
    ),
    _area(
        "Säkerhetskopiering",
        K1=dict(
            description="Regelbunden säkerhetskopiering.",
            keywords=["backup", "säkerhetskopiering", "data recovery"],
            regulatory_ref="NIS2 Art. 21(2)(c) · ISO 27001 A.8.13",
        ),
        K2=dict(
            description="Daglig säkerhetskopiering med regelbundet testad återställning.",
            keywords=["backup", "säkerhetskopiering", "restore", "återläsning", "återställningstest"],
            regulatory_ref="NIS2 Art. 21(2)(c) · DORA Art. 12 · ISO 27001 A.8.13",
        ),
    ),
    _area(
        "Kontinuitet och katastrofåterställning",
        K3=dict(
            description="Kontinuitetsplan och plan för katastrofåterställning med årlig övning. "
                        "Återställningstid högst 4 h, maximal dataförlust högst 1 h.",
            keywords=["disaster recovery", "business continuity", "katastrofåterställning",
                      "kontinuitetsplan", "drp", "bcp", "rto", "rpo", "failover"],
            regulatory_ref="NIS2 Art. 21(2)(c) · DORA Art. 11 · ISO 27001 A.5.29, A.5.30",
        ),
        K4=dict(
            description="Drift i flera geografiska regioner med regelbundna, kontrollerade störningstester. "
                        "Återställningstid högst 1 h, maximal dataförlust högst 15 min.",
            keywords=["multi-region", "active-active", "geo-redundant", "geografisk redundans",
                      "chaos engineering", "resilience testing", "high availability",
                      "hög tillgänglighet", "rto", "rpo"],
            regulatory_ref="NIS2 Art. 21(2)(c) · DORA Art. 11 · ISO 27001 A.5.30, A.8.14",
        ),
    ),
    _area(
        "Incidenthantering",
        K2=dict(
            description="Dokumenterad process för att hantera säkerhetsincidenter.",
            keywords=["incident response", "incident management", "incidenthantering",
                      "security incident", "säkerhetsincident"],
            regulatory_ref="NIS2 Art. 21(2)(b) · DORA Art. 17 · ISO 27001 A.5.24–A.5.26",
        ),
        K3=dict(
            description="Formell incidentprocess med rapportering enligt NIS2 (inom 24 h respektive 72 h) "
                        "och klassificering enligt DORA.",
            keywords=["incident response", "breach notification", "24 hours", "72 hours",
                      "incidentrapportering", "csirt"],
            regulatory_ref="NIS2 Art. 21(2)(b), Art. 23 · DORA Art. 17–19 · ISO 27001 A.5.24–A.5.28",
        ),
    ),
    _area(
        "Loggning och säkerhetsövervakning",
        K3=dict(
            description="Central loggning och övervakning av säkerhetshändelser (SIEM).",
            keywords=["siem", "security monitoring", "säkerhetsövervakning", "logging", "loggning",
                      "threat detection", "anomaly detection"],
            regulatory_ref="NIS2 Art. 21(2)(b) · DORA Art. 10 · ISO 27001 A.8.15, A.8.16",
        ),
        K4=dict(
            description="Säkerhetscenter (SOC) som bevakar dygnet runt, med hotunderrättelser och "
                        "automatiserad incidenthantering (SOAR).",
            keywords=["24/7", "24x7", "security operations center", "soar", "threat intelligence",
                      "hotunderrättelser", "managed detection"],
            regulatory_ref="NIS2 Art. 21(2)(b) · DORA Art. 10 · ISO 27001 A.5.7, A.8.16",
        ),
    ),
    _area(
        "Sårbarhetshantering och säkerhetstester",
        K2=dict(
            description="Regelbunden sårbarhetsskanning och en rutin för att åtgärda sårbarheter.",
            keywords=["vulnerability scanning", "vulnerability management", "sårbarhetsskanning",
                      "sårbarhetshantering", "patch management", "patchhantering"],
            regulatory_ref="NIS2 Art. 21(2)(e) · DORA Art. 9(4)(f) · ISO 27001 A.8.8",
        ),
        K3=dict(
            description="Årliga penetrationstester av oberoende part och en rutin för ansvarsfullt "
                        "avslöjande av sårbarheter.",
            keywords=["penetration test", "pentest", "penetrationstest", "responsible disclosure",
                      "vulnerability disclosure", "ethical hacking"],
            regulatory_ref="NIS2 Art. 21(2)(e) · DORA Art. 24–25 · ISO 27001 A.8.8",
        ),
        K4=dict(
            description="Penetrationstester varje halvår, hotbaserade penetrationstester (TLPT) och "
                        "belöningsprogram för rapporterade sårbarheter.",
            keywords=["tlpt", "threat-led penetration", "red team", "bug bounty", "penetration test",
                      "coordinated vulnerability disclosure"],
            regulatory_ref="NIS2 Art. 21(2)(e) · DORA Art. 24–27 · ISO 27001 A.8.8",
        ),
    ),
    _area(
        "Säker systemutveckling",
        K2=dict(
            description="Kodgranskning och automatisk kodanalys ingår i utvecklingsprocessen.",
            keywords=["code review", "kodgranskning", "sast", "static analysis", "statisk kodanalys",
                      "secure coding", "säker kodning"],
            regulatory_ref="NIS2 Art. 21(2)(e) · ISO 27001 A.8.25, A.8.28",
        ),
        K3=dict(
            description="Säker utvecklingsprocess med hotmodellering, säkerhetstester och obligatorisk "
                        "kodgranskning.",
            keywords=["secure sdlc", "sdlc", "secure development", "säker utveckling", "threat modeling",
                      "hotmodellering", "owasp", "devsecops", "dast"],
            regulatory_ref="NIS2 Art. 21(2)(e) · ISO 27001 A.8.25–A.8.29",
        ),
        K4=dict(
            description="Som för K3 samt signerade programpaket, förteckning över programvarukomponenter "
                        "(SBOM), oföränderlig infrastruktur och fyraögonsprincip vid driftsättning.",
            keywords=["sbom", "software bill of materials", "signed artifacts", "code signing",
                      "kodsignering", "immutable infrastructure", "slsa"],
            regulatory_ref="NIS2 Art. 21(2)(e) · DORA Art. 9(4)(e) · ISO 27001 A.8.25–A.8.29, A.8.32",
        ),
    ),
    _area(
        "Leverantörer och tredjepartsrisk",
        K2=dict(
            description="Servicenivåavtal (SLA) med grundläggande säkerhetskrav, även för underleverantörer.",
            keywords=["service level agreement", "servicenivåavtal", "service level", "subprocessor",
                      "underleverantör", "vendor management"],
            regulatory_ref="NIS2 Art. 21(2)(d) · DORA Art. 28 · ISO 27001 A.5.19, A.5.20",
        ),
        K3=dict(
            description="Detaljerade avtal med IKT-tredjepartsleverantörer, inklusive exitstrategier "
                        "och uppföljning av leverantörernas säkerhet.",
            keywords=["third party", "tredjepart", "exit strategy", "exitstrategi", "vendor risk",
                      "supply chain", "leverantörsbedömning", "subprocessor"],
            regulatory_ref="NIS2 Art. 21(2)(d) · DORA Art. 28–30 · ISO 27001 A.5.19–A.5.22",
        ),
        K4=dict(
            description="Som för K3 samt hantering av koncentrationsrisk och efterlevnad av EU:s "
                        "tillsynsram för kritiska IKT-leverantörer (DORA Art. 31).",
            keywords=["critical ict", "critical third party", "kritisk leverantör", "oversight framework",
                      "tillsynsram", "concentration risk", "koncentrationsrisk", "exit strategy"],
            regulatory_ref="NIS2 Art. 21(2)(d) · DORA Art. 28–31 · ISO 27001 A.5.19–A.5.22",
        ),
    ),
    _area(
        "Dataskydd och personuppgifter",
        K1=dict(
            description="Integritetspolicy som beskriver hur personuppgifter hanteras.",
            keywords=["privacy policy", "integritetspolicy", "personuppgifter", "personal data", "privacy"],
            regulatory_ref="GDPR Art. 13 · ISO 27001 A.5.34",
        ),
        K3=dict(
            description="Dokumenterad efterlevnad av GDPR med dataskyddsombud, konsekvensbedömningar "
                        "och personuppgiftsbiträdesavtal.",
            keywords=["gdpr", "general data protection", "dataskyddsförordningen", "data protection officer",
                      "dataskyddsombud", "dpia", "privacy impact assessment", "konsekvensbedömning",
                      "data processing agreement", "personuppgiftsbiträdesavtal"],
            regulatory_ref="GDPR Art. 28, 35, 37 · ISO 27001 A.5.34",
        ),
    ),
    _area(
        "Maskering av testdata",
        K3=dict(
            description="Data maskeras eller anonymiseras i test- och utvecklingsmiljöer.",
            keywords=["data masking", "datamaskning", "anonymization", "anonymisering",
                      "pseudonymization", "pseudonymisering", "test data", "testdata"],
            regulatory_ref="GDPR Art. 25 · ISO 27001 A.8.11, A.8.33",
        ),
    ),
    _area(
        "Fysisk säkerhet",
        K3=dict(
            description="Fysiskt skydd av datacenter och lokaler där informationen behandlas.",
            keywords=["physical security", "fysisk säkerhet", "physical access", "fysisk åtkomst",
                      "data center security", "datacenter security"],
            regulatory_ref="ISO 27001 A.7.1–A.7.4",
        ),
    ),
    _area(
        "Kortdata (PCI DSS)",
        K4=dict(
            description="Efterlevnad av PCI DSS om kortdata hanteras.",
            keywords=["pci dss", "payment card", "cardholder data", "kortdata"],
            certifications=["PCI DSS"],
            regulatory_ref="PCI DSS · ISO 27001 A.5.31",
        ),
    ),
]


def get_cumulative_requirements(level: str) -> list[Requirement]:
    """One requirement per area, using the strictest expectation up to the given level."""
    allowed = LEVEL_ORDER[: LEVEL_ORDER.index(level) + 1]
    result = []
    for area in REQUIREMENT_AREAS:
        applicable = [area[lvl] for lvl in allowed if lvl in area]
        if applicable:
            result.append(applicable[-1])
    return result
