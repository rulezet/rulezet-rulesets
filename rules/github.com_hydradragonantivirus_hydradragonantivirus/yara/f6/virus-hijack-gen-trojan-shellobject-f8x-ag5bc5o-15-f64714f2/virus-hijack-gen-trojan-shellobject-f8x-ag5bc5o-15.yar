rule Virus_Hijack_Gen_Trojan_ShellObject_f8X_aG5Bc5o_15 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8X@aG5Bc5o_15.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "47b0a947697ca4f69992a0bb7e5d533289067cd1e0d6c7b48765e4a8531a2d16"

  strings:
    $s1 = "I7hundred euros) in all purchase orders transacted" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}