rule Trojan_Danger_Generic_Dacic_1A7FA519_A_C87EBE91_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Generic.Dacic.1A7FA519.A.C87EBE91_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "98d393d421cfca66f7739d817b907777b30313f4cd3784644d96c009697f24d0"

  strings:
    $s1 = ";What if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}