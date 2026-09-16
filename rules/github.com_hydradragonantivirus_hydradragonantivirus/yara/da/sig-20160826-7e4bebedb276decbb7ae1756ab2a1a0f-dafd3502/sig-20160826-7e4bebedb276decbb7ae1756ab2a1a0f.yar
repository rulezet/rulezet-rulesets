rule sig_20160826_7e4bebedb276decbb7ae1756ab2a1a0f {
  meta:
    description = "datamaliciousorder - file 20160826_7e4bebedb276decbb7ae1756ab2a1a0f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b30241cfc8db858f11c86a0a7d7d04d016c4d69968230abfaffb01c58690758a"

  strings:
    $s1 = "var OAt1 = new Array(\"\\x0a\",\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x44\",\"\\x49\",\"\\x6c\",\"\\x3d\",\"\\x22\",\"\\x6f" ascii

  condition:
    uint16(0) == 0x760a and
    all of them
}