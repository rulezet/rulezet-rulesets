rule Virus_Hijack_Trojan_GenericKDZ_74550_302 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_302.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2dcabf2ec6fa5141a611660df1143161693249ced50116b063deef7072f08d29"

  strings:
    $s1 = "sANk*jn&Z" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}