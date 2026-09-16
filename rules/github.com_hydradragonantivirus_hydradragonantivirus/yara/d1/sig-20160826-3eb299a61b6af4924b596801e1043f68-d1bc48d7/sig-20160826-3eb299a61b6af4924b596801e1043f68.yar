rule sig_20160826_3eb299a61b6af4924b596801e1043f68 {
  meta:
    description = "datamaliciousorder - file 20160826_3eb299a61b6af4924b596801e1043f68.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "42fa05127ea8c1ada3c13fc7aea4d47e15efa09d9e1b794022301c63bbc41703"

  strings:
    $s1 = "var OAt1 = new Array(\"\\x0a\",\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x4d\",\"\\x6c\",\"\\x3d\",\"\\x22\",\"\\x65\",\"\\x2b" ascii

  condition:
    uint16(0) == 0x760a and
    all of them
}