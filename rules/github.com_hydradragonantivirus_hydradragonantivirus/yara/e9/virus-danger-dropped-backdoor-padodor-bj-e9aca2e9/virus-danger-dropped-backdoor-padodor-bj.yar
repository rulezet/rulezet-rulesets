rule Virus_Danger_Dropped_Backdoor_Padodor_BJ {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Dropped.Backdoor.Padodor.BJ.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "306a9841244da5ff82ab03e4c432beb0bc28be6ceec08bc42e4ae14a3945f3f0"

  strings:
    $s1 = "prevent either party from disclosing the terms o" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}