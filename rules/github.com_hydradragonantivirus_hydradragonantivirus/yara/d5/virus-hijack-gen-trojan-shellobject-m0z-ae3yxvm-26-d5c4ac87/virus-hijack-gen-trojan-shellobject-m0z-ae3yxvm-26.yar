rule Virus_Hijack_Gen_Trojan_ShellObject_m0Z_ae3yXvm_26 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m0Z@ae3yXvm_26.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "daf56b7c08b5df4240779c1da772549b59f72f3d9b687e7c12db9e2dd4988ed7"

  strings:
    $s1 = "B4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}