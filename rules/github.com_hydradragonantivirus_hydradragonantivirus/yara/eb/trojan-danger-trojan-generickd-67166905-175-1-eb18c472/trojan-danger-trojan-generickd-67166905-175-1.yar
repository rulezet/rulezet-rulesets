rule Trojan_Danger_Trojan_GenericKD_67166905_175_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_175_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "82e3b4deb7cff1361e4a178af1d66bc60f71a1dd703fe202ae90b9ca74cd7d69"

  strings:
    $s1 = "nOracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}