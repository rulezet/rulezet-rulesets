rule Virus_Danger_Gen_Trojan_ShellObject_eSW_amMcCQb {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Gen.Trojan.ShellObject.eSW@amMcCQb.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7b55ecbe6e3add2740617c85344b9045ce9c3123f011d906d3c3bfe91a7073e1"

  strings:
    $s1 = "vwhole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}