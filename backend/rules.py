# Contoh file konfigurasi aturan (rules.py)
# Dapat dikembangkan menjadi file JSON external untuk fleksibilitas
ATTACK_RULES = {
    "SQL Injection": {
        "patterns": [
            r".*('.+--|UNION|SELECT|DROP|EXEC).*$",
            r".*(%27|%22|').*(%3D|=|%3B).*",  # URL-encoded SQLi
            r".*xp_cmdshell.*$"  # SQL Server spesifik
        ],
        "severity": "High",
        "weight": 0.8  # Bobot untuk scoring
    },
    "Brute-Force": {
        "patterns": [
            r".*POST.*\/login.*401.*$",
            r".*Failed password for.*$",
            r".*Invalid user.*$"
        ],
        "severity": "Medium",
        "weight": 0.6
    },
    "XSS": {
        "patterns": [
            r".*<script>.*<\/script>.*$",
            r".*(onerror=|onload=).*\(\).*",
            r".*javascript:.*$"
        ],
        "severity": "Medium",
        "weight": 0.5
    },
    "Directory Traversal": {
        "patterns": [
            r".*(\.\.\/|\.\.\\).*",
            r".*root\/.*"
        ],
        "severity": "High",
        "weight": 0.7
    }
}