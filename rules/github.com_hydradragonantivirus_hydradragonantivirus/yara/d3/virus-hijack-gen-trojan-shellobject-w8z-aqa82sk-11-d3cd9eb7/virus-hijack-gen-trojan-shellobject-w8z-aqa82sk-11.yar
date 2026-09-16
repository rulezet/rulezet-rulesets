rule Virus_Hijack_Gen_Trojan_ShellObject_w8Z_aqA82Sk_11 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.w8Z@aqA82Sk_11.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bc46047071fd82d407a4768314ff2e0a8d7573067e20a417b57806ae748de554"

  strings:
    $s1 = "@zIRE_OLSA_V120103_Def_V122304 Page 7 of 11 " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}