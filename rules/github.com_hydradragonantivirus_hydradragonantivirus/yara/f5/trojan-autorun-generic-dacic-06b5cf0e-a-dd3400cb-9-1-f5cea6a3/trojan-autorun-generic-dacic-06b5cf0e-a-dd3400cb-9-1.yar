rule Trojan_Autorun_Generic_Dacic_06B5CF0E_A_DD3400CB_9_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Generic.Dacic.06B5CF0E.A.DD3400CB_9_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eea801de6a1842f4cf9c30be5046d3f9a86861131bb084f9fb27697b12816886"

  strings:
    $s1 = "epor service that is subject to a discount or a pr" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}