rule Virus_Hijack_Gen_Trojan_ShellObject_dyW_aGIb_Qk_11_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.dyW@aGIb!Qk_11_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a0b5ae953e5e849a2cfafa0c5592019c2245414c50de1610a6170ff920872382"

  strings:
    $s1 = ">?NiDe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}