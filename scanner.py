"""
Website scanner that fetches vendor pages, searches for third-party reviews,
and extracts security-related evidence.
"""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from urllib.parse import urljoin, urlparse, quote_plus

import httpx
from bs4 import BeautifulSoup

from classification import Requirement, get_cumulative_requirements

logger = logging.getLogger(__name__)

SECURITY_PATHS = [
    "/security",
    "/trust",
    "/trust-center",
    "/compliance",
    "/certifications",
    "/privacy",
    "/privacy-policy",
    "/gdpr",
    "/legal/security",
    "/legal/privacy",
    "/about/security",
    "/info/security",
    "/security-compliance",
    "/data-security",
    "/data-protection",
    "/sakerhet",
    "/integritet",
]

REVIEW_SEARCH_QUERIES = [
    "{vendor} security review",
    "{vendor} ISO 27001 SOC 2 certification",
    "{vendor} GDPR compliance review",
    "{vendor} penetration test security audit",
    "{vendor} data breach incident",
    "{vendor} encryption MFA security features",
    "{vendor} recension säkerhet",
]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "sv-SE,sv;q=0.9,en-US;q=0.8,en;q=0.7",
}

TIMEOUT = httpx.Timeout(15.0, connect=10.0)


@dataclass
class PageContent:
    url: str
    title: str
    text: str
    status: int
    found: bool = True


@dataclass
class ReviewResult:
    """A single third-party review/article/mention found via web search."""
    title: str
    url: str
    snippet: str
    source: str  # domain name of the review source


@dataclass
class Finding:
    area: str
    description: str
    regulatory_ref: str
    status: str  # "found", "partial", "not_found"
    evidence: list[str] = field(default_factory=list)
    matched_keywords: list[str] = field(default_factory=list)
    matched_certifications: list[str] = field(default_factory=list)
    source_urls: list[str] = field(default_factory=list)
    review_evidence: list[dict] = field(default_factory=list)


@dataclass
class ScanResult:
    vendor_url: str
    classification_level: str
    pages_scanned: list[str]
    pages_failed: list[str]
    findings: list[Finding]
    total_requirements: int
    requirements_met: int
    requirements_partial: int
    requirements_not_met: int
    score_percent: float
    summary: str
    reviews_found: list[dict] = field(default_factory=list)
    review_sources_scanned: int = 0


def _normalize(text: str) -> str:
    return re.sub(r"\s+", " ", text.lower().strip())


def _extract_text(html: str) -> str:
    soup = BeautifulSoup(html, "lxml")
    for tag in soup(["script", "style", "nav", "footer", "noscript", "svg"]):
        tag.decompose()
    return _normalize(soup.get_text(separator=" "))


def _extract_title(html: str) -> str:
    soup = BeautifulSoup(html, "lxml")
    title_tag = soup.find("title")
    return title_tag.get_text(strip=True) if title_tag else ""


def _extract_context(text: str, keyword: str, window: int = 120) -> str | None:
    """Pull a short snippet around a keyword match for evidence display."""
    idx = text.lower().find(keyword.lower())
    if idx == -1:
        return None
    start = max(0, idx - window)
    end = min(len(text), idx + len(keyword) + window)
    snippet = text[start:end].strip()
    if start > 0:
        snippet = "…" + snippet
    if end < len(text):
        snippet = snippet + "…"
    return snippet


async def _fetch_page(client: httpx.AsyncClient, url: str) -> PageContent:
    try:
        resp = await client.get(url, headers=HEADERS, timeout=TIMEOUT, follow_redirects=True)
        if resp.status_code == 200:
            html = resp.text
            return PageContent(
                url=str(resp.url),
                title=_extract_title(html),
                text=_extract_text(html),
                status=resp.status_code,
            )
        return PageContent(url=url, title="", text="", status=resp.status_code, found=False)
    except (httpx.RequestError, httpx.HTTPStatusError):
        return PageContent(url=url, title="", text="", status=0, found=False)


# ── Web search for third-party reviews ──

async def _search_duckduckgo(client: httpx.AsyncClient, query: str) -> list[dict]:
    """Search DuckDuckGo HTML and extract result titles, URLs, and snippets."""
    search_url = f"https://html.duckduckgo.com/html/?q={quote_plus(query)}"
    results = []
    try:
        resp = await client.get(
            search_url,
            headers={
                **HEADERS,
                "Referer": "https://duckduckgo.com/",
            },
            timeout=TIMEOUT,
            follow_redirects=True,
        )
        if resp.status_code != 200:
            return results

        soup = BeautifulSoup(resp.text, "lxml")
        for result_div in soup.select(".result"):
            title_tag = result_div.select_one(".result__a")
            snippet_tag = result_div.select_one(".result__snippet")
            if not title_tag:
                continue

            href = title_tag.get("href", "")
            # DuckDuckGo wraps URLs in a redirect; try to extract the real URL
            if "uddg=" in href:
                from urllib.parse import parse_qs, urlparse as _up
                qs = parse_qs(_up(href).query)
                href = qs.get("uddg", [href])[0]

            title = title_tag.get_text(strip=True)
            snippet = snippet_tag.get_text(strip=True) if snippet_tag else ""

            if not href.startswith("http"):
                continue

            parsed = urlparse(href)
            source_domain = parsed.netloc.replace("www.", "")

            results.append({
                "title": title,
                "url": href,
                "snippet": snippet,
                "source": source_domain,
            })

            if len(results) >= 5:
                break

    except Exception as e:
        logger.warning("DuckDuckGo search failed for %r: %s", query, e)

    return results


async def _fetch_review_page(client: httpx.AsyncClient, url: str) -> Optional[str]:
    """Fetch a review page and return its extracted text, or None on failure."""
    try:
        resp = await client.get(url, headers=HEADERS, timeout=TIMEOUT, follow_redirects=True)
        if resp.status_code == 200:
            return _extract_text(resp.text)
    except Exception:
        pass
    return None


async def _search_reviews(
    client: httpx.AsyncClient, vendor_name: str, vendor_domain: str,
) -> tuple[list[ReviewResult], dict[str, str]]:
    """
    Run multiple search queries for vendor reviews and return
    (deduplicated ReviewResults, {url: page_text} for fetched review pages).
    """
    all_results: list[ReviewResult] = []
    seen_urls: set[str] = set()

    for query_tpl in REVIEW_SEARCH_QUERIES:
        query = query_tpl.format(vendor=vendor_name)
        raw = await _search_duckduckgo(client, query)
        for r in raw:
            # Skip the vendor's own site — we already scan that directly
            if vendor_domain in r["url"]:
                continue
            if r["url"] in seen_urls:
                continue
            seen_urls.add(r["url"])
            all_results.append(ReviewResult(
                title=r["title"],
                url=r["url"],
                snippet=r["snippet"],
                source=r["source"],
            ))
        # Small delay between searches to be respectful
        await asyncio.sleep(0.5)

    # Fetch the top review pages (limit to avoid slowness)
    review_page_map: dict[str, str] = {}
    pages_to_fetch = all_results[:12]

    fetch_tasks = [_fetch_review_page(client, rv.url) for rv in pages_to_fetch]
    fetched_texts = await asyncio.gather(*fetch_tasks, return_exceptions=True)

    for rv, text in zip(pages_to_fetch, fetched_texts):
        if isinstance(text, str) and text.strip():
            review_page_map[rv.url] = text

    return all_results, review_page_map


def _check_requirement(
    req: Requirement,
    corpus: str,
    page_map: dict[str, str],
    review_corpus: str,
    review_page_map: dict[str, str],
    all_reviews: list[ReviewResult],
) -> Finding:
    """Check a single requirement against the vendor corpus AND review corpus."""
    matched_kw = []
    matched_certs = []
    evidence = []
    source_urls = []
    review_evidence: list[dict] = []

    # ── Check vendor's own pages ──
    for kw in req.keywords:
        if kw.lower() in corpus:
            matched_kw.append(kw)
            for url, page_text in page_map.items():
                ctx = _extract_context(page_text, kw)
                if ctx and url not in source_urls:
                    source_urls.append(url)
                    if len(evidence) < 3:
                        evidence.append(ctx)

    for cert in req.certifications:
        if cert.lower() in corpus:
            matched_certs.append(cert)
            for url, page_text in page_map.items():
                ctx = _extract_context(page_text, cert)
                if ctx and url not in source_urls:
                    source_urls.append(url)
                    if len(evidence) < 3:
                        evidence.append(ctx)

    # ── Check third-party reviews ──
    review_kw_matches = []
    review_cert_matches = []

    for kw in req.keywords:
        if kw.lower() in review_corpus:
            if kw not in matched_kw:
                review_kw_matches.append(kw)
            for url, page_text in review_page_map.items():
                ctx = _extract_context(page_text, kw, window=150)
                if ctx:
                    # Find the matching ReviewResult for title/source
                    rv_match = next((rv for rv in all_reviews if rv.url == url), None)
                    review_evidence.append({
                        "keyword": kw,
                        "snippet": ctx,
                        "url": url,
                        "source": rv_match.source if rv_match else urlparse(url).netloc,
                        "title": rv_match.title if rv_match else "",
                    })
                    if len(review_evidence) >= 5:
                        break
            if len(review_evidence) >= 5:
                break

    for cert in req.certifications:
        if cert.lower() in review_corpus:
            if cert not in matched_certs:
                review_cert_matches.append(cert)
            for url, page_text in review_page_map.items():
                ctx = _extract_context(page_text, cert, window=150)
                if ctx:
                    rv_match = next((rv for rv in all_reviews if rv.url == url), None)
                    review_evidence.append({
                        "keyword": cert,
                        "snippet": ctx,
                        "url": url,
                        "source": rv_match.source if rv_match else urlparse(url).netloc,
                        "title": rv_match.title if rv_match else "",
                    })
                    if len(review_evidence) >= 5:
                        break
            if len(review_evidence) >= 5:
                break

    # Deduplicate review evidence by URL
    seen_rv = set()
    unique_review_evidence = []
    for rv in review_evidence:
        key = (rv["url"], rv["keyword"])
        if key not in seen_rv:
            seen_rv.add(key)
            unique_review_evidence.append(rv)
    review_evidence = unique_review_evidence[:5]

    # ── Scoring: combine vendor site + review evidence ──
    all_kw = list(set(matched_kw + review_kw_matches))
    all_certs = list(set(matched_certs + review_cert_matches))

    total_indicators = len(req.keywords) + len(req.certifications)
    vendor_matched = len(matched_kw) + len(matched_certs)
    total_matched = len(all_kw) + len(all_certs)

    if total_matched == 0:
        status = "not_found"
    elif vendor_matched >= max(2, total_indicators * 0.4):
        status = "found"
    elif total_matched >= max(2, total_indicators * 0.4):
        # Reviews alone can boost to partial, or found if very strong
        status = "found" if vendor_matched > 0 else "partial"
    elif total_matched > 0:
        status = "partial"
    else:
        status = "not_found"

    if req.certifications and (matched_certs or review_cert_matches):
        if matched_certs:
            status = "found"
        elif review_cert_matches:
            status = "partial" if status == "not_found" else status

    return Finding(
        area=req.area,
        description=req.description,
        regulatory_ref=req.regulatory_ref,
        status=status,
        evidence=evidence,
        matched_keywords=all_kw,
        matched_certifications=all_certs,
        source_urls=source_urls,
        review_evidence=review_evidence,
    )


def _extract_vendor_name(url: str) -> str:
    """Derive a human-readable vendor name from the URL."""
    parsed = urlparse(url)
    host = parsed.netloc.replace("www.", "")
    # Take just the main domain part (e.g. "microsoft" from "microsoft.com")
    parts = host.split(".")
    if len(parts) >= 2:
        return parts[-2]  # e.g. "microsoft" from "microsoft.com"
    return host


async def scan_vendor(url: str, level: str) -> ScanResult:
    parsed = urlparse(url)
    if not parsed.scheme:
        url = "https://" + url
        parsed = urlparse(url)

    base_url = f"{parsed.scheme}://{parsed.netloc}"
    vendor_domain = parsed.netloc.replace("www.", "")
    vendor_name = _extract_vendor_name(url)

    urls_to_scan = [url]
    for path in SECURITY_PATHS:
        candidate = urljoin(base_url, path)
        if candidate not in urls_to_scan:
            urls_to_scan.append(candidate)

    pages_scanned = []
    pages_failed = []
    page_map: dict[str, str] = {}

    async with httpx.AsyncClient() as client:
        # Phase 1: Scan vendor's own pages
        for scan_url in urls_to_scan:
            page = await _fetch_page(client, scan_url)
            if page.found and page.text.strip():
                pages_scanned.append(page.url)
                page_map[page.url] = page.text
            else:
                pages_failed.append(scan_url)

        # Phase 2: Search for third-party reviews
        logger.info("Searching third-party reviews for %s", vendor_name)
        all_reviews, review_page_map = await _search_reviews(
            client, vendor_name, vendor_domain,
        )

    vendor_corpus = " ".join(page_map.values())
    review_corpus = " ".join(review_page_map.values())

    requirements = get_cumulative_requirements(level)
    findings = [
        _check_requirement(req, vendor_corpus, page_map, review_corpus, review_page_map, all_reviews)
        for req in requirements
    ]

    met = sum(1 for f in findings if f.status == "found")
    partial = sum(1 for f in findings if f.status == "partial")
    not_met = sum(1 for f in findings if f.status == "not_found")
    total = len(findings)
    score = ((met + partial * 0.5) / total * 100) if total else 0

    if score >= 80:
        summary = f"Leverantören visar god överensstämmelse med kraven för {level}."
    elif score >= 50:
        summary = f"Leverantören uppfyller delvis kraven för {level}. Kompletterande underlag bör begäras."
    else:
        summary = f"Leverantören visar begränsad överensstämmelse med kraven för {level}. Detaljerad granskning krävs."

    reviews_data = [
        {"title": rv.title, "url": rv.url, "snippet": rv.snippet, "source": rv.source}
        for rv in all_reviews
    ]

    return ScanResult(
        vendor_url=url,
        classification_level=level,
        pages_scanned=pages_scanned,
        pages_failed=pages_failed,
        findings=findings,
        total_requirements=total,
        requirements_met=met,
        requirements_partial=partial,
        requirements_not_met=not_met,
        score_percent=round(score, 1),
        summary=summary,
        reviews_found=reviews_data,
        review_sources_scanned=len(review_page_map),
    )
