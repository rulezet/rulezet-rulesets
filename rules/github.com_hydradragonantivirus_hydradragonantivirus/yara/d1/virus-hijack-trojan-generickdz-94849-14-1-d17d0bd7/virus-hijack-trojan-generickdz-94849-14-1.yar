rule Virus_Hijack_Trojan_GenericKDZ_94849_14_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.94849_14_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0325cb1693353473b8d9b2e8d448012507eb3f3082adbd0f7dcfe10843309a09"

  strings:
    $s1 = "*!aMic" fullword ascii
    $s2 = "PUGH>K" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}