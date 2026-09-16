rule Virus_Hijack_Trojan_GenericKDZ_105924_174_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_174_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a4f12af58202c3ebf293ce9a0cf47f35ca0a2075a41289d282be0e8fb8ec2845"

  strings:
    $s1 = "CreateFile Error" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}