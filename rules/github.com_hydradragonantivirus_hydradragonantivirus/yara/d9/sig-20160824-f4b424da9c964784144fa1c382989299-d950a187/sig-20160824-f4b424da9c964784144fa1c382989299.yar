rule sig_20160824_f4b424da9c964784144fa1c382989299 {
  meta:
    description = "datamaliciousorder - file 20160824_f4b424da9c964784144fa1c382989299.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c7296c06c115a05ca3a8f0628c9e88083ee5f59b7af88e206ec65c2b2713990b"

  strings:
    $s1 = "var DOh = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}