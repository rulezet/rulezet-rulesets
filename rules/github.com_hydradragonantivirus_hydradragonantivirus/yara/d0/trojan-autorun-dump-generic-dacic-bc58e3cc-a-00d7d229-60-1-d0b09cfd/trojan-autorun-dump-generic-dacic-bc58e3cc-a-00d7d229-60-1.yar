rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_60_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_60_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7634075ac2e2658d6872a914eb77862ccc827a49d796886f2405c3b82e2fd471"

  strings:
    $s1 = "YMyour entire employee population." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}