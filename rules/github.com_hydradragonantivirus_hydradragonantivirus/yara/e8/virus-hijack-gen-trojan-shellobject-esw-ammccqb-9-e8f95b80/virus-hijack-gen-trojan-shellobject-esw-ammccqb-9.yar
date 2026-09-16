rule Virus_Hijack_Gen_Trojan_ShellObject_eSW_amMcCQb_9 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.eSW@amMcCQb_9.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c672a3cae606cfc42f28fb3ad4b2cae301186680d8e66f659a4da2c193a25bcb"

  strings:
    $s1 = "#whole number for purposes of license quantity requirements." fullword ascii
    $s2 = "TWiT#_" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}