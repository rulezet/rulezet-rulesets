rule Virus_Hijack_Gen_Trojan_ShellObject_fyX_aWevApi_6_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fyX@aWevApi_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2ac8322efa9b06905fcf1fdd4951ee27d2bd976f147aa0ccbaba552845da80b4"

  strings:
    $s1 = "Profiler detected" fullword wide
    $s2 = "Loop broken" fullword wide
    $s3 = "`YaYa " fullword ascii
    $s4 = "waXY @" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}