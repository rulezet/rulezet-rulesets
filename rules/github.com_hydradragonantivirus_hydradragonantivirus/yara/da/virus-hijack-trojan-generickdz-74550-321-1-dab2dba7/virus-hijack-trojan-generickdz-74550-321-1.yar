rule Virus_Hijack_Trojan_GenericKDZ_74550_321_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_321_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ad89fbf1c5600b4fa9b381d98c7f920f7708635faf1f5bfe4c7fd87a4ce875ac"

  strings:
    $s1 = "Aheap``.g" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}