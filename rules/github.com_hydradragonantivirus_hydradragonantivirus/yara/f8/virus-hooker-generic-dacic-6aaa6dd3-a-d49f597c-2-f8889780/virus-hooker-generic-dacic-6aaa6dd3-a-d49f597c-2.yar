rule Virus_Hooker_Generic_Dacic_6AAA6DD3_A_D49F597C_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hooker_Generic.Dacic.6AAA6DD3.A.D49F597C_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8437230f9713502ee545984fb3ce1f55d2765ef5d8a79b1d6bf20f4f69d7eec7"

  strings:
    $s1 = "}()PAIr" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}