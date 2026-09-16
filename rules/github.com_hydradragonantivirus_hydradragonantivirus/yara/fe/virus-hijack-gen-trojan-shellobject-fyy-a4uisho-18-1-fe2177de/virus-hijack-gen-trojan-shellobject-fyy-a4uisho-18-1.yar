rule Virus_Hijack_Gen_Trojan_ShellObject_fyY_a4uiSHo_18_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fyY@a4uiSHo_18_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "29ce10ff0b83ed6cf3c91b305e7423d378af00112dffdbe29340b6c164aa423e"

  strings:
    $s1 = "Profiler detected" fullword wide
    $s2 = "Loop broken" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}