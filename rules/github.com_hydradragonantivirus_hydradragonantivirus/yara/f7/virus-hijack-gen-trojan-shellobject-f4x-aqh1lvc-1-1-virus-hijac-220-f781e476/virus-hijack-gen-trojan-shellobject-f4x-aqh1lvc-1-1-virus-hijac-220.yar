import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_f4X_aqH1LVc_1_1_Virus_Hijac_220 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.f4X@aqH1LVc_1_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@aeOesjp_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6c90326caea19664994b5634a9d69a5c057c0a8acc2295c83e2bbae73b89640d"
    hash2       = "6113c1c3af868d857c99f0d532423f2dee9962a2aeb07f374bfb54919348892b"

  strings:
    $s1 = ">execution" fullword ascii
    $s2 = "return," fullword ascii
    $s3 = "minute," fullword ascii
    $s4 = "folder," fullword ascii
    $s5 = "`associated" fullword ascii
    $s6 = "`string" fullword ascii
    $s7 = "month," fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "a9192bab5c7c795c7488b69a1853f9c2" and (all of them)
    ) or (all of them)
}