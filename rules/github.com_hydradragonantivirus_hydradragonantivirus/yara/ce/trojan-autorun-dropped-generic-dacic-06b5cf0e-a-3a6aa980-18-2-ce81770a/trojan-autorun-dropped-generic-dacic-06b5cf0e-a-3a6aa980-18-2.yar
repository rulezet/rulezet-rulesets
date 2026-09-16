rule Trojan_Autorun_Dropped_Generic_Dacic_06B5CF0E_A_3A6AA980_18_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dropped.Generic.Dacic.06B5CF0E.A.3A6AA980_18_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f090422da68bbd4e025cc9f066bec528478e1040ead416e84c9b05666d2ff3f2"

  strings:
    $s1 = ".net Framework must be installed" fullword wide
    $s2 = "S3 TRIO" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}