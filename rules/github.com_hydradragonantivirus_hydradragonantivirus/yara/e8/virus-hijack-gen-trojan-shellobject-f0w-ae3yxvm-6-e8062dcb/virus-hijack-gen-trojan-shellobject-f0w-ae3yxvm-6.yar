rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_ae3yXvm_6 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@ae3yXvm_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fc56c432933ff079ef798ce3eb7a5b5aacf4743c2dc821eadd46f61ead6398e1"

  strings:
    $s1 = "#4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}