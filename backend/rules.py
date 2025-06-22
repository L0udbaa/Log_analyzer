# Contoh file konfigurasi aturan (rules.py)
ATTACK_RULES = {
    "SQL Injection": {
        "patterns": [
            r".*('.+--|UNION|SELECT|DROP|EXEC).*$",
            r".*(%27|%22|').*(%3D|=|%3B).*",  # URL-encoded SQLi
            r".*xp_cmdshell.*$"  # SQL Server spesifik
        ],
        "severity": "High",
        "weight": 0.8,
        "how": "Dengan menyisipkan perintah SQL ke dalam input aplikasi, penyerang mencoba memanipulasi query database untuk mencuri atau merusak data."
    },
    "Brute-Force": {
        "patterns": [
            r".*POST.*\/login.*401.*$",
            r".*Failed password for.*$",
            r".*Invalid user.*$"
        ],
        "severity": "Medium",
        "weight": 0.6,
        "how": "Melibatkan percobaan login berulang kali menggunakan kombinasi username dan password yang berbeda untuk mendapatkan akses ilegal."
    },
    "XSS": {
        "patterns": [
            r"(?i)<\s*script.*?>.*?<\s*/\s*script\s*>",
            r"(?i)on\w+\s*=\s*['\"].*?['\"]",
            r"(?i)javascript\s*:",
            r"(?i)<\s*img[^>]*(onerror|onload)\s*=",
            r"(?i)<\s*iframe",
            r"(?i)<\s*svg.*on\w+\s*=",
            r"(?i)document\.cookie",
            r"(?i)window\.location",
            r"(?i)eval\s*\(",
            r"(?i)alert\s*\("
        ],
        "severity": "Medium",
        "weight": 0.5,
        "how": "Dengan menyisipkan skrip berbahaya ke dalam halaman web, penyerang dapat mencuri cookie, mengarahkan ulang pengguna, atau melakukan aksi atas nama korban."
    }
}
