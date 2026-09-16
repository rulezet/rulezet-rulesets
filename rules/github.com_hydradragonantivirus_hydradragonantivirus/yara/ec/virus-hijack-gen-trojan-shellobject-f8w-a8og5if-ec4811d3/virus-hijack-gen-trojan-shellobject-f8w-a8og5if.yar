rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_a8oG5if {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@a8oG5if.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "20b9e22dce3908ba172323f929da5c0df77810a05747210937e8cdbbc8cc13f1"

  strings:
    $s1 = "\\wby different names such as reseller, distributor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}