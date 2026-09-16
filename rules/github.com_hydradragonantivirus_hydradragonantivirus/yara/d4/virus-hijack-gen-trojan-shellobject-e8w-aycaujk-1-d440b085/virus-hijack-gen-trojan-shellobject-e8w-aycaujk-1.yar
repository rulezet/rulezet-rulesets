rule Virus_Hijack_Gen_Trojan_ShellObject_e8W_aycAujk_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8W@aycAujk_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f4fb22c66b93b9303601e0c0490204e1fe12176e3f9293744364cd5269ab1a89"

  strings:
    $s1 = "u:PoOR" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}