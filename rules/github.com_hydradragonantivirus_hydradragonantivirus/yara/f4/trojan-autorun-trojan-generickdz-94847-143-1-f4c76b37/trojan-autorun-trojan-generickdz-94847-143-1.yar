rule Trojan_Autorun_Trojan_GenericKDZ_94847_143_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_143_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8a36c37efd10ff5e64b9c597487a80704a64ec1fcbd18921e0de5908a0f77530"

  strings:
    $s1 = "HIRE_OLSA_V120103_Def_V122304 Page 7 of 11 " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}