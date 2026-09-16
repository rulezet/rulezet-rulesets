rule sig_20160823_d0c6baef5789777f928c8b2b7f12e541 {
  meta:
    description = "datamaliciousorder - file 20160823_d0c6baef5789777f928c8b2b7f12e541.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a84cd5128f1136d13afd5cc548de19899cc795480bc537c0afc5e97c8bbd4fd2"

  strings:
    $s1 = "var Ha8 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}