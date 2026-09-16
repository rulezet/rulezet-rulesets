rule sig_20160526_3659acf5279ec547579e6e73d4ddda13 {
  meta:
    description = "datamaliciousorder - file 20160526_3659acf5279ec547579e6e73d4ddda13.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6bc6a44a33512a3fdf7da85faa95a7ca8103cd4fb04491a87fa818c011497f11"

  strings:
    $s1 = "HURL rav\\n\\r;\"htg\" = 2hDMX rav\\n\\r;\"Cmorf\" = 4aRVWRIO rav\\n\\r;\"rah\" = dQOJ rav\\n\\r;\"edoC\" = lXLE rav\\n\\r;\"ioj" ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}