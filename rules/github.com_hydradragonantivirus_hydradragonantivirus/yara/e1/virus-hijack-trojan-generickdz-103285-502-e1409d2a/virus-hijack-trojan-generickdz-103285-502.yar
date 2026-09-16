rule Virus_Hijack_Trojan_GenericKDZ_103285_502 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_502.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e36511b13d6d9e366443515593ed52cdacc44bae6ab1b58541c2c2895665885c"

  strings:
    $s1 = "Z8dispute under this agreement to which Section B applies must be filed within one year in small claims" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}