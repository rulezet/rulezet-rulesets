rule Virus_Hijack_Trojan_GenericKDZ_74550_156_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_156_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f79e2df8158e57baea0d8a4a515084ef0e4ab21a56d105e74f76d5b134a9e834"

  strings:
    $s1 = "BEnj[!-" fullword ascii
    $s2 = "dUit!S" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}