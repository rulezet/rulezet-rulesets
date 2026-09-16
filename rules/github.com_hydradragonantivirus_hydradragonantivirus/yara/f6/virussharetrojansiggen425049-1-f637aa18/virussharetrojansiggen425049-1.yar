rule VirusShareTrojanSiggen425049_1 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanSiggen425049_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ef8e41cee50ae9efba2b9ab2098b787e5f59812b149a5162e573f2defd9e0015"

  strings:
    $s1 = "Cpas Locked" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}