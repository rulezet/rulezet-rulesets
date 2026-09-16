rule Virus_Danger_Gen_Trojan_ShellObject_k4Z_aSzGK_f {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Gen.Trojan.ShellObject.k4Z@aSzGK!f.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bca5d39390e94548b91a2e1280800a3cf55e9e383e7b877e94ef2b3039fd9f81"

  strings:
    $s1 = "eOracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}