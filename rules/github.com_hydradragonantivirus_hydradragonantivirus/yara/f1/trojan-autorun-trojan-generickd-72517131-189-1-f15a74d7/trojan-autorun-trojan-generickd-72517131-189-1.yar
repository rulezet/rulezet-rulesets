rule Trojan_Autorun_Trojan_GenericKD_72517131_189_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.72517131_189_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d6a5018b2a34f417b00cb45eb6771368eb76fea069536d0a63b5d126970a3f19"

  strings:
    $s1 = "gUser, Marketing User, Manufacturing User, Purcha" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}