rule Trojan_Autorun_Trojan_GenericKD_72517131_6_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.72517131_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "64d6a82af3343c7d1af48f452b2ee76ba75a77808159ac9ad794775b1f5987b7"

  strings:
    $s1 = "aUser, Marketing User, Manufacturing User, Purcha" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}