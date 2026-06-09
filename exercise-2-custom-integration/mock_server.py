"""
Mock Threat Intelligence REST API server.

Simulates a fictional TI provider with endpoints for IP reputation,
domain reputation, IOC search, and bulk retrieval.

Start: python mock_server.py
Listens on http://127.0.0.1:5000
"""

from flask import Flask, jsonify, request

app = Flask(__name__)

API_KEY = "test-api-key-12345"

# ─── Mock data ───────────────────────────────────────────────────────────

MOCK_IPS = {
    "8.8.8.8": {
        "ip": "8.8.8.8",
        "score": 5,
        "categories": ["search-engine", "dns"],
        "last_seen": "2026-06-08T12:00:00Z",
        "is_malicious": False,
    },
    "185.220.101.1": {
        "ip": "185.220.101.1",
        "score": 92,
        "categories": ["tor-exit-node", "proxy", "c2"],
        "last_seen": "2026-06-09T08:30:00Z",
        "is_malicious": True,
    },
    "192.168.1.1": {
        "ip": "192.168.1.1",
        "score": 0,
        "categories": ["private-range"],
        "last_seen": "2026-01-01T00:00:00Z",
        "is_malicious": False,
    },
}

MOCK_DOMAINS = {
    "google.com": {
        "domain": "google.com",
        "score": 5,
        "registrar": "MarkMonitor Inc.",
        "creation_date": "1997-09-15",
        "is_malicious": False,
    },
    "evil-phishing.xyz": {
        "domain": "evil-phishing.xyz",
        "score": 97,
        "registrar": "NameCheap",
        "creation_date": "2026-05-01",
        "is_malicious": True,
    },
    "suspicious-download.cc": {
        "domain": "suspicious-download.cc",
        "score": 68,
        "registrar": "GoDaddy",
        "creation_date": "2025-11-20",
        "is_malicious": False,
    },
}

MOCK_HASHES = {
    "d41d8cd98f00b204e9800998ecf8427e": {
        "type": "hash",
        "value": "d41d8cd98f00b204e9800998ecf8427e",
        "score": 0,
        "file_type": "empty",
        "detections": 0,
        "is_malicious": False,
    },
    "e99a18c428cb38d5f260853678922e03": {
        "type": "hash",
        "value": "e99a18c428cb38d5f260853678922e03",
        "score": 95,
        "file_type": "PE32 executable",
        "detections": 52,
        "is_malicious": True,
    },
}

ALL_IOCS = []

def _build_ioc_index():
    """Build a flat IOC list from mock data for search."""
    for ip_data in MOCK_IPS.values():
        ALL_IOCS.append({
            "type": "ip",
            "value": ip_data["ip"],
            "score": ip_data["score"],
            "categories": ip_data["categories"],
            "last_seen": ip_data["last_seen"],
            "is_malicious": ip_data["is_malicious"],
        })
    for dom_data in MOCK_DOMAINS.values():
        ALL_IOCS.append({
            "type": "domain",
            "value": dom_data["domain"],
            "score": dom_data["score"],
            "registrar": dom_data["registrar"],
            "creation_date": dom_data["creation_date"],
            "is_malicious": dom_data["is_malicious"],
        })
    for hash_data in MOCK_HASHES.values():
        ALL_IOCS.append(hash_data)

_build_ioc_index()


# ─── Auth middleware ──────────────────────────────────────────────────────

def check_auth():
    auth = request.headers.get("Authorization", "")
    if auth != f"Bearer {API_KEY}":
        return jsonify({"error": "Unauthorized", "message": "Invalid or missing API key"}), 401
    return None


# ─── Routes ──────────────────────────────────────────────────────────────

@app.route("/health", methods=["GET"])
def health():
    err = check_auth()
    if err:
        return err
    return jsonify({"status": "ok", "version": "1.0.0"})


@app.route("/api/v1/ip/<ip>/reputation", methods=["GET"])
def ip_reputation(ip):
    err = check_auth()
    if err:
        return err
    if ip in MOCK_IPS:
        return jsonify(MOCK_IPS[ip])
    # Unknown IPs get a neutral response
    return jsonify({
        "ip": ip,
        "score": 25,
        "categories": ["unknown"],
        "last_seen": None,
        "is_malicious": False,
    })


@app.route("/api/v1/domain/<domain>/reputation", methods=["GET"])
def domain_reputation(domain):
    err = check_auth()
    if err:
        return err
    if domain in MOCK_DOMAINS:
        return jsonify(MOCK_DOMAINS[domain])
    return jsonify({
        "domain": domain,
        "score": 20,
        "registrar": "Unknown",
        "creation_date": None,
        "is_malicious": False,
    })


@app.route("/api/v1/ioc/search", methods=["GET"])
def ioc_search():
    err = check_auth()
    if err:
        return err

    query = request.args.get("query", "").lower()
    ioc_type = request.args.get("type", "").lower()
    limit = int(request.args.get("limit", 10))

    results = []
    for ioc in ALL_IOCS:
        # Type filter
        if ioc_type and ioc.get("type", "").lower() != ioc_type:
            continue
        # Query match (substring on value or categories)
        value = ioc.get("value", "").lower()
        categories = [c.lower() for c in ioc.get("categories", [])]
        if query in value or any(query in c for c in categories):
            results.append(ioc)

    return jsonify({
        "query": query,
        "type_filter": ioc_type or None,
        "total_results": len(results),
        "results": results[:limit],
    })


@app.route("/api/v1/iocs/bulk", methods=["GET"])
def iocs_bulk():
    err = check_auth()
    if err:
        return err
    limit = int(request.args.get("limit", 100))
    offset = int(request.args.get("offset", 0))
    return jsonify({
        "total": len(ALL_IOCS),
        "limit": limit,
        "offset": offset,
        "iocs": ALL_IOCS[offset:offset + limit],
    })


# ─── Run ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("Mock TI API server starting on http://127.0.0.1:5000")
    print(f"Required API key: {API_KEY}")
    app.run(host="127.0.0.1", port=5000, debug=False)
