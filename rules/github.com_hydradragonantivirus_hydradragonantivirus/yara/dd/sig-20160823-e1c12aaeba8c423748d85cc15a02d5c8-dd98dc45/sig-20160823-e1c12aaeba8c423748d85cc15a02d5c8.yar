rule sig_20160823_e1c12aaeba8c423748d85cc15a02d5c8 {
  meta:
    description = "datamaliciousorder - file 20160823_e1c12aaeba8c423748d85cc15a02d5c8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b52cb76bdf1a11e56fff048067e4b746dab635ea5fdfed216029b869d7719a3e"

  strings:
    $s1 = "var Ha8 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}