rule Trojan_Autorun_Trojan_GenericKDZ_94847_275_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_275_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0f94b3d4704881a7b693f83c70a345c462ccebc8e4fb48e76f35fd8801130678"

  strings:
    $s1 = "VIRE_OLSA_V120103_Def_V122304 Page 7 of 11 " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}