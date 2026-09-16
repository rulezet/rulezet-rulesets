rule Virus_Hijack_Gen_Trojan_ShellObject_mWZ_aeFgVVo {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.mWZ@aeFgVVo.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "144967b29c94e63312c804a209b35c882b980be8126279508be34e60855d0fe0"

  strings:
    $s1 = "user minimum table in the licensing rules section" fullword ascii
    $s2 = "b]shall be counted." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}