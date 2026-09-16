rule Virus_Hijack_Gen_Trojan_ShellObject_m8Z_aGRF3ml_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m8Z@aGRF3ml_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f0fb98f7ff6de51a8a76aa37fe7a473d502a878b9cce9cfa37a71468c0638616"

  strings:
    $s1 = "*RUN*HIDE;F:\\" fullword ascii
    $s2 = "Product Planning Dept.1" fullword ascii
    $s3 = "*PROTECT" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}