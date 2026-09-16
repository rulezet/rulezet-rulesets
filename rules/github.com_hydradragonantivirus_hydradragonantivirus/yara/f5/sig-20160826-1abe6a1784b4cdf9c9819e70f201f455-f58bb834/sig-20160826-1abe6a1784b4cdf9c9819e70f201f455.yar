rule sig_20160826_1abe6a1784b4cdf9c9819e70f201f455 {
  meta:
    description = "datamaliciousorder - file 20160826_1abe6a1784b4cdf9c9819e70f201f455.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ca31205b5a21988ea18289fff1ded33f562be0eb8c84da240c52a96cd66a5cb4"

  strings:
    $s1 = "var OAt1 = new Array(\"\\x0a\",\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x46\",\"\\x57\",\"0\",\"\\x3d\",\"\\x22\",\"\\x65\"," ascii

  condition:
    uint16(0) == 0x760a and
    all of them
}