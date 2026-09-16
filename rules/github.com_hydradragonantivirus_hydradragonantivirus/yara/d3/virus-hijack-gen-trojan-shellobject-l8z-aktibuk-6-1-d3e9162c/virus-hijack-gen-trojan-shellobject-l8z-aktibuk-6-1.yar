rule Virus_Hijack_Gen_Trojan_ShellObject_l8Z_aKTibuk_6_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.l8Z@aKTibuk_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f384ded729fd7bf92383bf1ee12b4e3da92fbb01ef0e9d84bf439ba70525210d"

  strings:
    $s1 = "ISAPI filter module" fullword wide
    $s2 = "kD_w@vFui^F|z{hadE]g3gtutNXLfL{|pAapUesfrDD7|~{a`_QlaabnkJZ|z{hadE]g+gtutNXLfXp~g^^" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}