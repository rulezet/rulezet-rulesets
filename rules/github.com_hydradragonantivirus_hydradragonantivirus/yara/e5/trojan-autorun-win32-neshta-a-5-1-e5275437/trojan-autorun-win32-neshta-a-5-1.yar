rule Trojan_Autorun_Win32_Neshta_A_5_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Win32.Neshta.A_5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "343b39c3e4c72105422f74d3d59a4fc74562c1996f98c19755e953c1e8945118"

  strings:
    $s1 = "'IRE_OLSA_V120103_Def_V122304 Page 1 of 11 " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}