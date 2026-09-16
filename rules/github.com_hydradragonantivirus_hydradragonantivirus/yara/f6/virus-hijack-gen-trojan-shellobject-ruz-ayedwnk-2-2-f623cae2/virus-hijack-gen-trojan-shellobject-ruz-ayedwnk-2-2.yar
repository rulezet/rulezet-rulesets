rule Virus_Hijack_Gen_Trojan_ShellObject_ruZ_ayeDwnk_2_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.ruZ@ayeDwnk_2_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fc6720c4ebd7a4929bf5161c741189c1c1cbfb341f692da339d46782bc63881d"

  strings:
    $s1 = "Orientation,%B" fullword ascii
    $s2 = "Color@'B" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}