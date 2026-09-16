rule Virus_Hijack_Trojan_GenericKDZ_103285_254 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_254.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3e14bf9e0c2a56fa247466c615a224e9a96adf3ff7e79dd06d017eb74a9b045a"

  strings:
    $s1 = "Xmicrosoft.com/office/backup. You may not distribute the backup copy of the software. You may use it" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}