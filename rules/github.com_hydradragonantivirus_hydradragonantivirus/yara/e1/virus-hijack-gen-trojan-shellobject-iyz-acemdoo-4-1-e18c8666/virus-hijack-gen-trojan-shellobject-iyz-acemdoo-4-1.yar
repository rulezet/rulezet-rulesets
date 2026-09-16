rule Virus_Hijack_Gen_Trojan_ShellObject_IyZ_aCEmdoo_4_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.IyZ@aCEmdoo_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "75abd08e8edaaa3f33f1e2cf2a04d51ade2837dd655ad68ff3bf5513cfc4db53"

  strings:
    $s1 = "GUGU?@" fullword ascii
    $s2 = "wOKe[2" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}