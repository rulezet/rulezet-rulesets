rule Virus_Hijack_Gen_Trojan_ShellObject_f8X_auLSMIo_6_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8X@auLSMIo_6_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e3c0e4da1cf6cd7575c772176e2369884d93e75d1cfeb101c2d132368b37b851"

  strings:
    $s1 = "chocolatey - shim" fullword wide
    $s2 = "0.10.5 - shim 0.8.1" fullword wide
    $s3 = " 2017 Chocolatey Software, Inc.. Copyright " fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}