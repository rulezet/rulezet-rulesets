rule Virus_Hijack_Gen_Trojan_ShellObject_m0Z_ae3yXvm_6 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m0Z@ae3yXvm_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0a4d5901e4115f8b5b0ca4b53764387bc81dab8e6b29e9b412dd99f2167a77a7"

  strings:
    $s1 = "V4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}