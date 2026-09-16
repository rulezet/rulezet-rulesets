rule sig_20160823_1671bbfd6fe2c37b5d151b570da1f757 {
  meta:
    description = "datamaliciousorder - file 20160823_1671bbfd6fe2c37b5d151b570da1f757.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6802477b4dfdd3a0f6a32b7285609d5f734a621f5c9a69f9f7cfa5f1874199a9"

  strings:
    $s1 = "var Ha8 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}