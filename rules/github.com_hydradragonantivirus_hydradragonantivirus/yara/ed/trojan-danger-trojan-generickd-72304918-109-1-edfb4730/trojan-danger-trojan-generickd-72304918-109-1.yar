rule Trojan_Danger_Trojan_GenericKD_72304918_109_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72304918_109_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "055852c5f66cd95b9b2d9e83139785c579f0e5a402e84e98aaf8661ef906b7ff"

  strings:
    $s1 = "HsOracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}