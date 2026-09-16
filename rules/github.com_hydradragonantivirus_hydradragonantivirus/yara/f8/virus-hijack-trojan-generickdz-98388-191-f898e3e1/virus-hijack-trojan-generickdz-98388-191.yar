rule Virus_Hijack_Trojan_GenericKDZ_98388_191 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_191.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3375462c7b99a020eb9047a11c7f75d9b0cf201cb97de28279429251a5414a14"

  strings:
    $s1 = "%will be " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}