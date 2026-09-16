rule sig_20160823_d4f2e40e068a4ed48869bd9d7aa6f0dc {
  meta:
    description = "datamaliciousorder - file 20160823_d4f2e40e068a4ed48869bd9d7aa6f0dc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5f90c5a361d6ba2ba58e9864acdd8c374f8e592bf89a201a313582af37da77be"

  strings:
    $s1 = "var Ha8 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}