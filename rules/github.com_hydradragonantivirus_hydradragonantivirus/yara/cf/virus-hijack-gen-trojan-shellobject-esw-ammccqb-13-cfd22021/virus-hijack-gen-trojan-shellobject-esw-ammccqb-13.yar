rule Virus_Hijack_Gen_Trojan_ShellObject_eSW_amMcCQb_13 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.eSW@amMcCQb_13.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b6128576471ebbcd19a024ef41f7c4033420b04a5bb1a9bf84c12b3702d872a6"

  strings:
    $s1 = ">whole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}