rule Virus_Hijack_Gen_Trojan_ShellObject_xSZ_amMcCQb_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.xSZ@amMcCQb_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "52d59987aa200067b2d1d0504916fc16d1c9c4eebfce2fea461310ac452018ce"

  strings:
    $s1 = ">whole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}