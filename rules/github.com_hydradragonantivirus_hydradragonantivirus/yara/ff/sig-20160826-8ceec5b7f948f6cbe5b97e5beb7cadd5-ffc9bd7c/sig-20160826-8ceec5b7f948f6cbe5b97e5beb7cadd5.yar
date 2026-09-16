rule sig_20160826_8ceec5b7f948f6cbe5b97e5beb7cadd5 {
  meta:
    description = "datamaliciousorder - file 20160826_8ceec5b7f948f6cbe5b97e5beb7cadd5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7f7094d8313a8247ecd77a1830ba586996c29617b3eda078e867ade728460e5e"

  strings:
    $s1 = "var OAt1 = new Array(\"\\x0a\",\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x4f\",\"3\",\"\\x3d\",\"\\x22\",\"\\x73\",\"\\x65\"," ascii
    $s2 = "var OAt1 = new Array(\"\\x0a\",\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x4f\",\"3\",\"\\x3d\",\"\\x22\",\"\\x73\",\"\\x65\"," ascii

  condition:
    uint16(0) == 0x760a and
    all of them
}