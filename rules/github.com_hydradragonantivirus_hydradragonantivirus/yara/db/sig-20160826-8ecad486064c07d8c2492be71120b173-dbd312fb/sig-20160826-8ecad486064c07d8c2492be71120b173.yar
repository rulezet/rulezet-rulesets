rule sig_20160826_8ecad486064c07d8c2492be71120b173 {
  meta:
    description = "datamaliciousorder - file 20160826_8ecad486064c07d8c2492be71120b173.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8a5b498f5517758b993ea473c2a8f174caae874869697991d194e3b421d2bb36"

  strings:
    $s1 = "var OAt1 = new Array(\"\\x0a\",\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x4d\",\"\\x6c\",\"\\x3d\",\"\\x22\",\"\\x65\",\"\\x2b" ascii

  condition:
    uint16(0) == 0x760a and
    all of them
}