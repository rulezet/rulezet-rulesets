rule Virus_Hijack_Gen_Trojan_ShellObject_fWW_a0tiwSg_5 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fWW@a0tiwSg_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "74a5a9681a3358f9f511d92e5f494ea71d1c2cc1ec62581f1158c2abb30f29b8"

  strings:
    $s1 = "xThis agreement is governed by the substantive and procedural laws of Ireland without reference to its conflictof laws principle" ascii
    $s2 = "xThis agreement is governed by the substantive and procedural laws of Ireland without reference to its conflictof laws principle" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}