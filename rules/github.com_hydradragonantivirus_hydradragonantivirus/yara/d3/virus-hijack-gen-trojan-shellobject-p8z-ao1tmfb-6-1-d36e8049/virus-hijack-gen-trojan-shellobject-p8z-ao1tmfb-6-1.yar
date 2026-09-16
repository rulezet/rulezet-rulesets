rule Virus_Hijack_Gen_Trojan_ShellObject_p8Z_aO1tmfb_6_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.p8Z@aO1tmfb_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a9c424071501eef45b9b832d4481963193248defc965705e149239dcd3b9d718"

  strings:
    $s1 = "c:\\users\\masterhyp\\documents\\visual studio 2012\\Projects\\WindowsApplication5\\WindowsApplication5\\obj\\Debug\\WindowsAppl" ascii
    $s2 = "c:\\users\\masterhyp\\documents\\visual studio 2012\\Projects\\WindowsApplication5\\WindowsApplication5\\obj\\Debug\\WindowsAppl" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}