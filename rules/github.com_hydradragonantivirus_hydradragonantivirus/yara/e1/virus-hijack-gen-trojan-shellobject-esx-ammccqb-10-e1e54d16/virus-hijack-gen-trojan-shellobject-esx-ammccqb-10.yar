rule Virus_Hijack_Gen_Trojan_ShellObject_eSX_amMcCQb_10 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.eSX@amMcCQb_10.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "310b2c5e72328ec0e8ee58ce4962d4f413fa7b632fa7a8ea477910cb501f7873"

  strings:
    $s1 = "1whole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}