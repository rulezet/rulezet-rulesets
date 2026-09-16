rule Virus_Hijack_Gen_Trojan_ShellObject_i8Z_a8oG5if {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i8Z@a8oG5if.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0760fed2c71041e6d363eac7720d4e22e5f439ed2437c84aa2967745e8f64715"

  strings:
    $s1 = "*by different names such as reseller, distributor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}