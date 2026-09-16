rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_418 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_418.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9b8ae0b6aa0cce5891c5f22ff617e1dae88eedd6a06138d60edb4a0897a6b7a1"

  strings:
    $s1 = "prevent either party from disclosing the terms o" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}