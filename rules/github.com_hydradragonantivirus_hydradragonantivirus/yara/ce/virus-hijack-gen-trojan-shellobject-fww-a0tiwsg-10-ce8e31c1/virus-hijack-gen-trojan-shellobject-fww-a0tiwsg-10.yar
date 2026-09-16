rule Virus_Hijack_Gen_Trojan_ShellObject_fWW_a0tiwSg_10 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fWW@a0tiwSg_10.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "54032e66790bdac4ee2aec9975da8d847af13ccb548ccaf9bfbb547ea2f4fc39"

  strings:
    $s1 = "5|This agreement is governed by the substantive and procedural laws of Ireland without reference to its conflictof laws principl" ascii
    $s2 = "5|This agreement is governed by the substantive and procedural laws of Ireland without reference to its conflictof laws principl" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}