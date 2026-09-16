rule Virus_Hijack_Gen_Trojan_ShellObject_k4Z_aSzGK_f_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.k4Z@aSzGK!f_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8c89b42cf06245cfcafd9c4735fcffaa3e58d9e6de84555ed1144abdcaba183a"

  strings:
    $s1 = "\"aOracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}