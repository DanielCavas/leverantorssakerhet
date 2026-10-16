"""
Information classification model K1–K4 with security requirements
mapped to NIS2 and DORA articles.
"""

from dataclasses import dataclass, field


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

# Each requirement level maps to what is EXPECTED at that classification.
# The scanner checks whether the vendor's site provides evidence for these.

REQUIREMENTS: dict[str, list[Requirement]] = {
    "K1": [
        Requirement(
            area="Grundläggande IT-säkerhet",
            description="Grundläggande IT-policy och säkerhetsrutiner bör finnas.",
            keywords=["security", "säkerhet", "it-policy", "privacy policy", "integritetspolicy"],
            regulatory_ref="NIS2 Art. 21 (allmänt)",
        ),
        Requirement(
            area="Transportkryptering",
            description="Kryptering av externa anslutningar med TLS 1.2 eller senare.",
            keywords=["tls", "ssl", "https", "encryption", "kryptering", "encrypted"],
            regulatory_ref="NIS2 Art. 21(2)(h)",
        ),
        Requirement(
            area="Säkerhetskopiering",
            description="Regelbunden säkerhetskopiering.",
            keywords=["backup", "säkerhetskopiering", "data recovery"],
            regulatory_ref="NIS2 Art. 21(2)(c)",
        ),
    ],
    "K2": [
        Requirement(
            area="Informationssäkerhetspolicy",
            description="Dokumenterad informationssäkerhetspolicy.",
            keywords=["information security policy", "informationssäkerhetspolicy", "security policy",
                       "säkerhetspolicy", "isms"],
            certifications=["ISO 27001"],
            regulatory_ref="NIS2 Art. 21",
        ),
        Requirement(
            area="Åtkomstkontroll",
            description="Rollbaserad åtkomstkontroll (RBAC) och stark lösenordspolicy.",
            keywords=["rbac", "role-based", "access control", "åtkomstkontroll", "behörighetsstyrning",
                       "strong password", "lösenordspolicy", "mfa", "multi-factor", "tvåfaktorsautentisering"],
            regulatory_ref="NIS2 Art. 21(2)(i) · DORA Art. 9(4)",
        ),
        Requirement(
            area="Kryptering",
            description="TLS 1.2 eller senare för all trafik. Kryptering av lagringsdiskar rekommenderas.",
            keywords=["tls", "encryption at rest", "kryptering i vila", "disk encryption",
                       "aes", "encrypted", "kryptering"],
            regulatory_ref="NIS2 Art. 21(2)(h) · DORA Art. 9(2)",
        ),
        Requirement(
            area="Incidenthantering",
            description="Dokumenterad incidentprocess.",
            keywords=["incident response", "incident management", "incidenthantering",
                       "security incident", "säkerhetsincident", "breach notification"],
            regulatory_ref="NIS2 Art. 23 · DORA Art. 17",
        ),
        Requirement(
            area="Säkerhetskopiering och återställning",
            description="Daglig säkerhetskopiering med testad återställning.",
            keywords=["backup", "disaster recovery", "business continuity", "rto", "rpo",
                       "katastrofåterställning", "återställning"],
            regulatory_ref="NIS2 Art. 21(2)(c) · DORA Art. 11",
        ),
        Requirement(
            area="Sårbarhetsskanning",
            description="Grundläggande sårbarhetsskanning, t.ex. automatisk kodanalys vid varje ny programversion.",
            keywords=["vulnerability scanning", "sast", "code review", "kodgranskning",
                       "sårbarhetsskanning", "secure development"],
            regulatory_ref="NIS2 Art. 21(2)(e) · DORA Art. 7",
        ),
        Requirement(
            area="Leverantörshantering",
            description="Servicenivåavtal (SLA) med grundläggande säkerhetskrav.",
            keywords=["sla", "service level", "subprocessor", "underleverantör",
                       "vendor management", "supply chain"],
            regulatory_ref="DORA Art. 28",
        ),
    ],
    "K3": [
        Requirement(
            area="Certifierat ledningssystem för informationssäkerhet",
            description="Certifierat ledningssystem för informationssäkerhet (ISO 27001 eller motsvarande).",
            keywords=["isms", "information security management", "ledningssystem"],
            certifications=["ISO 27001", "ISO 27017", "ISO 27018"],
            regulatory_ref="NIS2 Art. 21 · DORA Art. 5-6",
        ),
        Requirement(
            area="Oberoende granskningsrapport",
            description="Rapport från oberoende granskning, t.ex. SOC 2 Typ II eller ISAE 3402.",
            keywords=["soc 2", "soc2", "soc ii", "type ii", "type 2", "isae 3402",
                       "isae3402", "ssae 18", "service organization control"],
            certifications=["SOC 2", "SOC 2 Type II", "ISAE 3402", "SSAE 18"],
            regulatory_ref="DORA Art. 5-6",
        ),
        Requirement(
            area="Obligatorisk flerfaktorsautentisering",
            description="Flerfaktorsautentisering (MFA) är obligatorisk för alla användare.",
            keywords=["mfa", "multi-factor", "multifactor", "two-factor", "2fa",
                       "tvåfaktor", "flerfaktorsautentisering"],
            regulatory_ref="NIS2 Art. 21(2)(i) · DORA Art. 9(4)",
        ),
        Requirement(
            area="Kryptering (avancerad)",
            description="AES-256-kryptering av lagrad data. TLS 1.3 och ömsesidig TLS (mTLS) mellan tjänster.",
            keywords=["aes-256", "aes 256", "tls 1.3", "mtls", "mutual tls",
                       "encryption at rest", "kryptering i vila", "end-to-end encryption"],
            certifications=["PCI DSS"],
            regulatory_ref="NIS2 Art. 21(2)(h) · DORA Art. 9(2)",
        ),
        Requirement(
            area="Nyckelhantering",
            description="Dedikerat system för nyckelhantering (KMS) med regelbundet nyckelbyte.",
            keywords=["kms", "key management", "nyckelhantering", "key rotation",
                       "hsm", "hardware security module"],
            regulatory_ref="NIS2 Art. 21(2)(h)",
        ),
        Requirement(
            area="Säkerhetsövervakning",
            description="Central logganalys (SIEM) och bevakning från ett säkerhetscenter (SOC), under kontorstid eller dygnet runt.",
            keywords=["siem", "soc", "security operations center", "security monitoring",
                       "övervakning", "threat detection", "anomaly detection"],
            regulatory_ref="DORA Art. 8",
        ),
        Requirement(
            area="Incidenthantering (NIS2/DORA)",
            description="Formell incidentprocess med rapportering enligt NIS2 (inom 24 h respektive 72 h) och klassificering enligt DORA.",
            keywords=["incident response", "incident management", "24 hour", "72 hour",
                       "breach notification", "csirt", "cert", "incidentrapportering"],
            regulatory_ref="NIS2 Art. 23 · DORA Art. 17-19",
        ),
        Requirement(
            area="Penetrationstest",
            description="Årliga penetrationstester. Krav på hotbaserade penetrationstester (TLPT) kan gälla (DORA Art. 26).",
            keywords=["penetration test", "pentest", "pen test", "tlpt", "red team",
                       "threat-led", "penetrationstest", "ethical hacking"],
            regulatory_ref="NIS2 Art. 21(2)(e) · DORA Art. 26",
        ),
        Requirement(
            area="Säker systemutveckling",
            description="Säker utvecklingsprocess med hotmodellering och obligatorisk kodgranskning.",
            keywords=["secure sdlc", "sdlc", "threat modeling", "hotmodellering",
                       "owasp", "secure development", "devsecops", "sast", "dast", "sca"],
            regulatory_ref="NIS2 Art. 21(2)(e) · DORA Art. 7-8",
        ),
        Requirement(
            area="Kontinuitet och katastrofåterställning",
            description="Kontinuitetsplan och plan för katastrofåterställning med årlig övning. Återställningstid högst 4 h, maximal dataförlust högst 1 h.",
            keywords=["disaster recovery", "business continuity", "drp", "bcp",
                       "rto", "rpo", "failover", "high availability", "hög tillgänglighet"],
            regulatory_ref="NIS2 Art. 21(2)(c) · DORA Art. 11-12",
        ),
        Requirement(
            area="Hantering av IKT-tredjepartsleverantörer",
            description="Detaljerade avtal med IKT-tredjepartsleverantörer, inklusive exitstrategier.",
            keywords=["third party", "tredjepartsrisk", "exit strategy", "exitstrategi",
                       "vendor risk", "supply chain", "leverantörsbedömning", "subprocessor"],
            regulatory_ref="DORA Art. 28-30",
        ),
        Requirement(
            area="Datamaskning",
            description="Maskering av data i test- och utvecklingsmiljöer.",
            keywords=["data masking", "datamaskning", "anonymization", "anonymisering",
                       "pseudonymization", "pseudonymisering", "test data"],
            regulatory_ref="GDPR Art. 25 · DORA Art. 9",
        ),
        Requirement(
            area="GDPR-efterlevnad",
            description="Fullständig GDPR-efterlevnad dokumenterad.",
            keywords=["gdpr", "general data protection", "dataskyddsförordningen",
                       "data protection officer", "dpo", "dataskyddsombud",
                       "privacy impact assessment", "konsekvensbedömning"],
            certifications=["GDPR"],
            regulatory_ref="GDPR",
        ),
    ],
    "K4": [
        Requirement(
            area="ISO 27001 med utökade certifieringar",
            description="ISO 27001 med tillägg för molntjänster (ISO 27017/27018). CSA STAR nivå 2 eller högre.",
            keywords=["iso 27001", "iso 27017", "iso 27018", "csa star", "cloud security alliance"],
            certifications=["ISO 27001", "ISO 27017", "ISO 27018", "CSA STAR"],
            regulatory_ref="NIS2 Art. 21 · DORA Art. 5-6",
        ),
        Requirement(
            area="SOC 2 Typ II och SOC 1",
            description="Granskningsrapporter enligt SOC 2 Typ II och SOC 1. Oberoende revision av tredje part.",
            keywords=["soc 2 type ii", "soc 1", "soc2", "isae 3402", "isae 3000",
                       "third-party audit", "tredjepartsrevision", "oberoende granskning"],
            certifications=["SOC 2 Type II", "SOC 1", "ISAE 3402"],
            regulatory_ref="DORA Art. 5-6",
        ),
        Requirement(
            area="Hårdvarunyckel och privilegierad åtkomst",
            description="Flerfaktorsautentisering med hårdvarunyckel. System för privilegierad åtkomst (PAM) med sessionsloggning och tidsbegränsad åtkomst.",
            keywords=["hardware token", "fido2", "fido", "yubikey", "pam", "privileged access",
                       "privilegierad åtkomst", "just-in-time", "jit access", "4-eyes",
                       "dual control", "session recording"],
            regulatory_ref="NIS2 Art. 21(2)(i) · DORA Art. 9(4)",
        ),
        Requirement(
            area="HSM-baserad kryptering",
            description="AES-256 med nycklar i en hårdvarusäkerhetsmodul (HSM). TLS 1.3, ömsesidig TLS och certifikatlåsning.",
            keywords=["hsm", "hardware security module", "aes-256", "certificate pinning",
                       "certifikatpinning", "mtls", "end-to-end", "zero knowledge"],
            regulatory_ref="NIS2 Art. 21(2)(h) · DORA Art. 9(2)",
        ),
        Requirement(
            area="Säkerhetscenter dygnet runt",
            description="Säkerhetscenter (SOC) dygnet runt med hotunderrättelser och automatiserad incidenthantering (SOAR).",
            keywords=["24x7", "24/7", "soc", "soar", "threat intelligence",
                       "hotintelligens", "automated response", "managed detection"],
            regulatory_ref="DORA Art. 8",
        ),
        Requirement(
            area="Obligatoriska hotbaserade penetrationstester",
            description="Penetrationstest varje halvår. Hotbaserade penetrationstester (TLPT) är obligatoriska (DORA Art. 26). Belöningsprogram för rapporterade sårbarheter.",
            keywords=["tlpt", "threat-led penetration", "red team", "bug bounty",
                       "responsible disclosure", "coordinated vulnerability"],
            regulatory_ref="DORA Art. 26",
        ),
        Requirement(
            area="Hög tillgänglighet och störningstester",
            description="Drift i flera geografiska regioner. Återställningstid högst 1 h, maximal dataförlust högst 15 min. Regelbundna, kontrollerade störningstester.",
            keywords=["multi-region", "active-active", "geo-redundant", "chaos engineering",
                       "resilience testing", "zero downtime", "rto", "rpo"],
            regulatory_ref="NIS2 Art. 21(2)(c) · DORA Art. 11-12",
        ),
        Requirement(
            area="Tillsyn av kritiska IKT-leverantörer",
            description="EU:s tillsynsram för kritiska IKT-leverantörer (DORA Art. 31).",
            keywords=["critical ict", "critical third party", "oversight framework",
                       "tillsynsram", "kritisk leverantör", "concentration risk"],
            regulatory_ref="DORA Art. 28-31",
        ),
        Requirement(
            area="PCI DSS (vid kortdata)",
            description="Efterlevnad av PCI DSS om kortdata hanteras.",
            keywords=["pci dss", "pci", "payment card", "cardholder data", "kortdata"],
            certifications=["PCI DSS"],
            regulatory_ref="PCI DSS",
        ),
        Requirement(
            area="Oföränderlig infrastruktur",
            description="Signerade programpaket. Oföränderlig infrastruktur. Fyraögonsprincip vid driftsättning.",
            keywords=["immutable infrastructure", "signed artifacts", "supply chain security",
                       "sbom", "software bill of materials", "code signing"],
            regulatory_ref="NIS2 Art. 21(2)(e) · DORA Art. 7",
        ),
    ],
}


def get_cumulative_requirements(level: str) -> list[Requirement]:
    """K-levels are cumulative: K3 includes K1+K2+K3 requirements."""
    order = ["K1", "K2", "K3", "K4"]
    idx = order.index(level)
    result = []
    for lvl in order[: idx + 1]:
        result.extend(REQUIREMENTS[lvl])
    return result
