rule Virus_Hijack_Trojan_GenericKDZ_103285_333 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_333.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fa383c145637175de992513cae439a112c923b9bf18e25b7b53094d5cccd4f11"

  strings:
    $s1 = "y8Oracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}