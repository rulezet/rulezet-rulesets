rule Virus_Hijack_Gen_Trojan_ShellObject_fWW_a0tiwSg_7 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fWW@a0tiwSg_7.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dbdce411d89977d6c32414b2159d3e9f393a37d6b825f189f8726d127361e8e7"

  strings:
    $s1 = "TThis agreement is governed by the substantive and procedural laws of Ireland without reference to its conflictof laws principle" ascii
    $s2 = "TThis agreement is governed by the substantive and procedural laws of Ireland without reference to its conflictof laws principle" ascii
    $s3 = "e`:crEE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}