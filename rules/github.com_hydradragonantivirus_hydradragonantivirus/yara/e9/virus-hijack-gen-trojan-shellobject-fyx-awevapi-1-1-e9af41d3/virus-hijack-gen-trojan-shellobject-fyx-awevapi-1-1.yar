rule Virus_Hijack_Gen_Trojan_ShellObject_fyX_aWevApi_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fyX@aWevApi_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "af2469f8acde2d498fd0d8fd091b4d469089d4a56606ea014a3b840c8e82d354"

  strings:
    $s1 = "<description>Java(TM) SE extcheck process</description>" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}