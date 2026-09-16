rule Virus_Hijack_Gen_Trojan_ShellObject_m0Z_ae3yXvm_31 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m0Z@ae3yXvm_31.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5496dcf26b4fadee0c2606755ce09b529476ff9c001fb19f779c1606e5a788dc"

  strings:
    $s1 = "Y4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}