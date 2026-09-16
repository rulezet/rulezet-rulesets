rule Virus_Hijack_Gen_Trojan_ShellObject_kAZ_aCEmdoo_3_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.kAZ@aCEmdoo_3_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4a662ce934413502f2d45199f2a56abaabddf7132c64333b6c93c7fae7c84e6d"

  strings:
    $s1 = "}ScUp]%@}" fullword ascii
    $s2 = "RCG(SYA&BeLy" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}