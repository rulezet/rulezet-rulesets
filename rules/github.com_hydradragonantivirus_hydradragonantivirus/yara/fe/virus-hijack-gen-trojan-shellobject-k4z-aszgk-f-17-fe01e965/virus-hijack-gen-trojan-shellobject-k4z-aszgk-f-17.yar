rule Virus_Hijack_Gen_Trojan_ShellObject_k4Z_aSzGK_f_17 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.k4Z@aSzGK!f_17.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "43e17b9e4e4e9543d43bb04a064c13e24f6ff8a06531e750cd7aad9c4fa952dc"

  strings:
    $s1 = "hOracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}