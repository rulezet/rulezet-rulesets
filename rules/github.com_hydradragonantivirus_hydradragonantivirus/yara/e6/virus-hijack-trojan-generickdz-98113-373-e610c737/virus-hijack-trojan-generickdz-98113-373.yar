rule Virus_Hijack_Trojan_GenericKDZ_98113_373 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_373.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b53380470f4ae86eeb3918357aac246bb1454cf1ab1d92d1b5c570ba3b3c7b6f"

  strings:
    $s1 = "7or service that is subject to a discount or a pr" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}