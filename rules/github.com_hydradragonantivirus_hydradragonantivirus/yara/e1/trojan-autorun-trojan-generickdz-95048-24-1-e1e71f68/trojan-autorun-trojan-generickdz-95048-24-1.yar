rule Trojan_Autorun_Trojan_GenericKDZ_95048_24_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.95048_24_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3f4bbf543193df7853b4d9d8b49ce9e22daee96a2635a5d55d109de4596d8ce5"

  strings:
    $s1 = "Cyou received the software, and also any Microsoft updates, supplements, and services for the software," fullword ascii
    $s2 = "and you and Oracle agree to submit to the exc`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}