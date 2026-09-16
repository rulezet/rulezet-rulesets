rule Trojan_Autorun_Trojan_GenericKDZ_94847_185_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_185_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7f9ba58712abf57992d29c63ce037dc53ca09efda830377a98f5b2d975f772f0"

  strings:
    $s1 = "<IRE_OLSA_V120103_Def_V122304 Page 1 of 11 " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}