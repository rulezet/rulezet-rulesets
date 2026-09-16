rule Virus_Hijack_Trojan_GenericKDZ_98113_353 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_353.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9e97dc7cc078721d13b06c5d18c0bb8028e33c5f5102bbe098b082eb478fa183"

  strings:
    $s1 = "LePA@X_" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}