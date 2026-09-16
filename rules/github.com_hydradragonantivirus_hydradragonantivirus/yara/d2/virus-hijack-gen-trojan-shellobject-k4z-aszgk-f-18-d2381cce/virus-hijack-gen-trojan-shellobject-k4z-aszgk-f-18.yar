rule Virus_Hijack_Gen_Trojan_ShellObject_k4Z_aSzGK_f_18 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.k4Z@aSzGK!f_18.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ddffa683e10c3ed40b7c5e6a21f0aad549379086752b3a1aa57753ee2f8c59dc"

  strings:
    $s1 = "#jOracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}