rule Virus_Hijack_Gen_Trojan_ShellObject_fyX_aWevApi_12_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fyX@aWevApi_12_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c011cfcc88e2274538ff140b073490916ec861bf00bf6ac2715bbc08f560d7ac"

  strings:
    $s1 = "ture=\"X86\" name=\"Adobe.Acrobat.AcrobatInfo\" type=\"win32\"></assemblyIdentity><description>Adobe Acrobat PDF Info 7.0</descr" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}