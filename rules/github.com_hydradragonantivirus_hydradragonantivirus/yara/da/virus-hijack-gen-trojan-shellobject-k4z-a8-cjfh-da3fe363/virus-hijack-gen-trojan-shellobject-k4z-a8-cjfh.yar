rule Virus_Hijack_Gen_Trojan_ShellObject_k4Z_a8_cJFh {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.k4Z@a8!cJFh.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "58e11e45fc3ff172ae98268e98d428ae321044ddee48f80df0ee3d9545ea79d2"

  strings:
    $s1 = "<UOracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii
    $s2 = "StIM'm#H" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}