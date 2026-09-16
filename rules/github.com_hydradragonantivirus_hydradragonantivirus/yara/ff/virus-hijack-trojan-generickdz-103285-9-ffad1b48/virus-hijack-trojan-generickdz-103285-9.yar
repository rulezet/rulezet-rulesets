rule Virus_Hijack_Trojan_GenericKDZ_103285_9 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_9.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ec8ba7bcf111c88ac09446e0bd7895d67db95ee691c7d29727ec01bde70174ab"

  strings:
    $s1 = "baOracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}