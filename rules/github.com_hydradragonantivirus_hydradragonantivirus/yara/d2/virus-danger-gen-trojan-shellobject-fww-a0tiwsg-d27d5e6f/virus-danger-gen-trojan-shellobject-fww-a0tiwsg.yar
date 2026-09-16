rule Virus_Danger_Gen_Trojan_ShellObject_fWW_a0tiwSg {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Gen.Trojan.ShellObject.fWW@a0tiwSg.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "823c4a5ae5ec06aedb8d62e11cfc7c9e46661d90507184a4d6af05103d0d0f54"

  strings:
    $s1 = "6This agreement is governed by the substantive and procedural laws of Ireland without reference to its conflictof laws principl" ascii
    $s2 = "6This agreement is governed by the substantive and procedural laws of Ireland without reference to its conflictof laws principl" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}