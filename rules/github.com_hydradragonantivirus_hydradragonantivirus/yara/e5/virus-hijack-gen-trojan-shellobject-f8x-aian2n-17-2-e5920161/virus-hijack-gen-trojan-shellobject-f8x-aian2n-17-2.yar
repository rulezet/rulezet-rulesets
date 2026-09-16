rule Virus_Hijack_Gen_Trojan_ShellObject_f8X_aian2n_17_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8X@aian2n_17_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "64729cc7c444516b204d35de902bb5df54a52982563c2b140b846d6e97fb66c5"

  strings:
    $s1 = "|C:\\Program Files\\Microsoft Visual Studio\\VB98\\Wizards\\APPWIZ.oca" fullword ascii
    $s2 = "Use Mask Color" fullword ascii
    $s3 = "Linear Chrome" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}