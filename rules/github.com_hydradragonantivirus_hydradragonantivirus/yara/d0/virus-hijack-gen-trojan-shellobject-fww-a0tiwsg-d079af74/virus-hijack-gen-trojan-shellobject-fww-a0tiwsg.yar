rule Virus_Hijack_Gen_Trojan_ShellObject_fWW_a0tiwSg {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fWW@a0tiwSg.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "158d99865da748f41c7800aa5191939e80f1d961a099d284b5c194a7b1408d0a"

  strings:
    $s1 = "7This agreement is governed by the substantive and procedural laws of Ireland without reference to its conflictof laws principle" ascii
    $s2 = "7This agreement is governed by the substantive and procedural laws of Ireland without reference to its conflictof laws principle" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}