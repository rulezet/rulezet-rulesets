rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_98 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_98.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5ee508711f03d05f5ba2a0ccdc28671e7c76f5d3da58f636bc9fa822992b0789"

  strings:
    $s1 = "TKprevent either party from disclosing the terms o" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}