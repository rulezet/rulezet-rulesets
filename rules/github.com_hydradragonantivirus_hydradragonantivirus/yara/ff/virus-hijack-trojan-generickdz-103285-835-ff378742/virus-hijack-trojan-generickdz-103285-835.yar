rule Virus_Hijack_Trojan_GenericKDZ_103285_835 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_835.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "da359d28290999fba733e60741d4c2b09187267c7d78eafa976a7c070f983d9d"

  strings:
    $s1 = "xWhat if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}