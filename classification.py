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
            description="TLS 1.2+ för externa anslutningar.",
            keywords=["tls", "ssl", "https", "encryption", "kryptering", "encrypted"],
            regulatory_ref="NIS2 Art. 21(2)(h)",
        ),
        Requirement(
            area="Backup",
            description="Regelbundna backuper.",
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
            description="TLS 1.2+ för all trafik. Diskkryptering rekommenderas.",
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
            area="Backup och återställning",
            description="Daglig backup med testad återställning.",
            keywords=["backup", "disaster recovery", "business continuity", "rto", "rpo",
                       "katastrofåterställning", "återställning"],
            regulatory_ref="NIS2 Art. 21(2)(c) · DORA Art. 11",
        ),
        Requirement(
            area="Sårbarhetsskanning",
            description="Grundläggande sårbarhetsskanning (SAST i CI/CD).",
            keywords=["vulnerability scanning", "sast", "code review", "kodgranskning",
                       "sårbarhetsskanning", "secure development"],
            regulatory_ref="NIS2 Art. 21(2)(e) · DORA Art. 7",
        ),
        Requirement(
            area="Leverantörshantering",
            description="SLA med grundläggande säkerhetskrav.",
            keywords=["sla", "service level", "subprocessor", "underleverantör",
                       "vendor management", "supply chain"],
            regulatory_ref="DORA Art. 28",
        ),
    ],
    "K3": [
        Requirement(
            area="ISMS och certifiering",
            description="Certifierat ledningssystem för informationssäkerhet (ISO 27001 eller motsvarande).",
            keywords=["isms", "information security management", "ledningssystem"],
            certifications=["ISO 27001", "ISO 27017", "ISO 27018"],
            regulatory_ref="NIS2 Art. 21 · DORA Art. 5-6",
        ),
        Requirement(
            area="SOC-rapport",
            description="SOC 2 Type II eller motsvarande oberoende granskning.",
            keywords=["soc 2", "soc2", "soc ii", "type ii", "type 2", "isae 3402",
                       "isae3402", "ssae 18", "service organization control"],
            certifications=["SOC 2", "SOC 2 Type II", "ISAE 3402", "SSAE 18"],
            regulatory_ref="DORA Art. 5-6",
        ),
        Requirement(
            area="MFA obligatorisk",
            description="Multifaktorautentisering (MFA) obligatorisk för alla användare.",
            keywords=["mfa", "multi-factor", "multifactor", "two-factor", "2fa",
                       "tvåfaktor", "flerfaktorsautentisering"],
            regulatory_ref="NIS2 Art. 21(2)(i) · DORA Art. 9(4)",
        ),
        Requirement(
            area="Kryptering (avancerad)",
            description="AES-256 kryptering i vila. TLS 1.3 och mTLS för tjänst-till-tjänst.",
            keywords=["aes-256", "aes 256", "tls 1.3", "mtls", "mutual tls",
                       "encryption at rest", "kryptering i vila", "end-to-end encryption"],
            certifications=["PCI DSS"],
            regulatory_ref="NIS2 Art. 21(2)(h) · DORA Art. 9(2)",
        ),
        Requirement(
            area="Nyckelhantering",
            description="Dedikerat KMS med nyckelrotation.",
            keywords=["kms", "key management", "nyckelhantering", "key rotation",
                       "hsm", "hardware security module"],
            regulatory_ref="NIS2 Art. 21(2)(h)",
        ),
        Requirement(
            area="SIEM och SOC",
            description="SIEM-integration och SOC-övervakning (8x5 eller 24x7).",
            keywords=["siem", "soc", "security operations center", "security monitoring",
                       "övervakning", "threat detection", "anomaly detection"],
            regulatory_ref="DORA Art. 8",
        ),
        Requirement(
            area="Incidenthantering (NIS2/DORA)",
            description="Formell incidentprocess med NIS2-rapportering (24h/72h) och DORA-klassificering.",
            keywords=["incident response", "incident management", "24 hour", "72 hour",
                       "breach notification", "csirt", "cert", "incidentrapportering"],
            regulatory_ref="NIS2 Art. 23 · DORA Art. 17-19",
        ),
        Requirement(
            area="Penetrationstest",
            description="Årliga penetrationstester. TLPT-krav kan gälla (DORA Art. 26).",
            keywords=["penetration test", "pentest", "pen test", "tlpt", "red team",
                       "threat-led", "penetrationstest", "ethical hacking"],
            regulatory_ref="NIS2 Art. 21(2)(e) · DORA Art. 26",
        ),
        Requirement(
            area="Secure SDLC",
            description="Secure SDLC med threat modeling och obligatorisk kodgranskning.",
            keywords=["secure sdlc", "sdlc", "threat modeling", "hotmodellering",
                       "owasp", "secure development", "devsecops", "sast", "dast", "sca"],
            regulatory_ref="NIS2 Art. 21(2)(e) · DORA Art. 7-8",
        ),
        Requirement(
            area="Kontinuitet och DRP",
            description="DRP + BCP med årlig övning. RTO ≤ 4h / RPO ≤ 1h.",
            keywords=["disaster recovery", "business continuity", "drp", "bcp",
                       "rto", "rpo", "failover", "high availability", "hög tillgänglighet"],
            regulatory_ref="NIS2 Art. 21(2)(c) · DORA Art. 11-12",
        ),
        Requirement(
            area="ICT-tredjepartshantering",
            description="Detaljerade ICT-tredjepartsavtal med exitstrategier.",
            keywords=["third party", "tredjepartsrisk", "exit strategy", "exitstrategi",
                       "vendor risk", "supply chain", "leverantörsbedömning", "subprocessor"],
            regulatory_ref="DORA Art. 28-30",
        ),
        Requirement(
            area="Datamaskning",
            description="Maskering av data i icke-produktionsmiljöer.",
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
            area="ISO 27001 + utvidgade certifieringar",
            description="ISO 27001 med utvidgning (27017/27018). CSA STAR Level 2+.",
            keywords=["iso 27001", "iso 27017", "iso 27018", "csa star", "cloud security alliance"],
            certifications=["ISO 27001", "ISO 27017", "ISO 27018", "CSA STAR"],
            regulatory_ref="NIS2 Art. 21 · DORA Art. 5-6",
        ),
        Requirement(
            area="SOC 2 Type II + SOC 1",
            description="SOC 2 Type II och SOC 1 rapporter. Oberoende tredjepartsrevision.",
            keywords=["soc 2 type ii", "soc 1", "soc2", "isae 3402", "isae 3000",
                       "third-party audit", "tredjepartsrevision", "oberoende granskning"],
            certifications=["SOC 2 Type II", "SOC 1", "ISAE 3402"],
            regulatory_ref="DORA Art. 5-6",
        ),
        Requirement(
            area="Hårdvaru-MFA och PAM",
            description="MFA med hårdvarutoken. PAM-lösning med sessionsloggning och tidsbegränsad åtkomst.",
            keywords=["hardware token", "fido2", "fido", "yubikey", "pam", "privileged access",
                       "privilegierad åtkomst", "just-in-time", "jit access", "4-eyes",
                       "dual control", "session recording"],
            regulatory_ref="NIS2 Art. 21(2)(i) · DORA Art. 9(4)",
        ),
        Requirement(
            area="HSM-baserad kryptering",
            description="AES-256 med HSM-hanterade nycklar. TLS 1.3, mTLS, certifikatpinning.",
            keywords=["hsm", "hardware security module", "aes-256", "certificate pinning",
                       "certifikatpinning", "mtls", "end-to-end", "zero knowledge"],
            regulatory_ref="NIS2 Art. 21(2)(h) · DORA Art. 9(2)",
        ),
        Requirement(
            area="24x7 SOC med threat intelligence",
            description="24x7 SOC med threat intelligence och automatiserad incidentrespons (SOAR).",
            keywords=["24x7", "24/7", "soc", "soar", "threat intelligence",
                       "hotintelligens", "automated response", "managed detection"],
            regulatory_ref="DORA Art. 8",
        ),
        Requirement(
            area="TLPT obligatoriskt",
            description="Halvårsvis penetrationstest. TLPT obligatoriskt (DORA Art. 26). Bug bounty-program.",
            keywords=["tlpt", "threat-led penetration", "red team", "bug bounty",
                       "responsible disclosure", "coordinated vulnerability"],
            regulatory_ref="DORA Art. 26",
        ),
        Requirement(
            area="Multi-region HA och chaos engineering",
            description="Multi-region HA. RTO ≤ 1h / RPO ≤ 15 min. Chaos engineering.",
            keywords=["multi-region", "active-active", "geo-redundant", "chaos engineering",
                       "resilience testing", "zero downtime", "rto", "rpo"],
            regulatory_ref="NIS2 Art. 21(2)(c) · DORA Art. 11-12",
        ),
        Requirement(
            area="Kritisk ICT-leverantörskontroll",
            description="EU:s tillsynsram för kritiska ICT-leverantörer (DORA Art. 31).",
            keywords=["critical ict", "critical third party", "oversight framework",
                       "tillsynsram", "kritisk leverantör", "concentration risk"],
            regulatory_ref="DORA Art. 28-31",
        ),
        Requirement(
            area="PCI DSS (vid kortdata)",
            description="PCI DSS-efterlevnad om kortdata hanteras.",
            keywords=["pci dss", "pci", "payment card", "cardholder data", "kortdata"],
            certifications=["PCI DSS"],
            regulatory_ref="PCI DSS",
        ),
        Requirement(
            area="Immutable infrastructure",
            description="Signerade artefakter. Immutable infrastructure. 4-eyes deploy-godkännande.",
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
