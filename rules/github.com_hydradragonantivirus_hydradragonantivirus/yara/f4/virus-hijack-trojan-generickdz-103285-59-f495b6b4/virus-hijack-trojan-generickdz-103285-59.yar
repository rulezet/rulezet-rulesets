rule Virus_Hijack_Trojan_GenericKDZ_103285_59 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_59.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7282af24d05ce1671982e6483387c788faac0ab26baf495b7ad2b9902027e061"

  strings:
    $s1 = "{virtualization, see the Additional Terms." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}