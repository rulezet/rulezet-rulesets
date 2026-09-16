rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_aGAMRTl_19_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@aGAMRTl_19_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "17ae98c9786ec0cfb6f9565b918781c7a171f823945cb54daa4c24dac174e563"

  strings:
    $x1 = "c:\\Users\\Administrator\\Documents\\Visual Studio 2012\\Projects\\sandford\\sandford\\obj\\Release\\sandford.pdb" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*)
}