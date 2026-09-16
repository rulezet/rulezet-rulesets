rule Virus_Sysbot_Dump_Generic_Dialer_34ECF9D6_4 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Dump.Generic.Dialer.34ECF9D6_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "71d3f8d176cfe9bbff1358a05de863225c9d1b2dcda60e461f503d5ad8ae7428"

  strings:
    $s1 = "foXY$LU" fullword ascii
    $s2 = "RiMy?<" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}