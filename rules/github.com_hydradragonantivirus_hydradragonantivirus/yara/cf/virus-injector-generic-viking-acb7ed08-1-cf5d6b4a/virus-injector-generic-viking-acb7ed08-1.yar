rule Virus_Injector_Generic_Viking_ACB7ED08_1 {
  meta:
    description = "datamaliciousorder - file Virus.Injector_Generic.Viking.ACB7ED08_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fad3dad9c013efee685083addfd2c1762738f2e694d3989763d496785f481dfd"

  strings:
    $s1 = "bijA&y" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}