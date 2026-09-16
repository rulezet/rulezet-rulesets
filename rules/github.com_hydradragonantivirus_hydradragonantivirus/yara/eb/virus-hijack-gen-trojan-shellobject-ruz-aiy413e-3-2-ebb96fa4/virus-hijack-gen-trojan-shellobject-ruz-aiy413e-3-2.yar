rule Virus_Hijack_Gen_Trojan_ShellObject_ruZ_aiy413e_3_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.ruZ@aiy413e_3_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4a534decaf5d11bd6658628abcb95c73b666b291c71ca71fb27d5b8e1c2e2072"

  strings:
    $s1 = "command is %s" fullword ascii
    $s2 = "%s\\Internet Explorer" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}