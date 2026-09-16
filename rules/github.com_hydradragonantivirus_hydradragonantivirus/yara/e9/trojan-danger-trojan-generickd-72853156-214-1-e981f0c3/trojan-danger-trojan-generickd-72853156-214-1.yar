rule Trojan_Danger_Trojan_GenericKD_72853156_214_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_214_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "59ff0efe1e552248bbe0d6afd1a27ab7af9944f10925c84cb099664e31bfa5a7"

  strings:
    $s1 = "those features in any way that cSysqamqqvaqqdSysqemdlwytSysqemoglnmSysqemvoxutSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaq" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}