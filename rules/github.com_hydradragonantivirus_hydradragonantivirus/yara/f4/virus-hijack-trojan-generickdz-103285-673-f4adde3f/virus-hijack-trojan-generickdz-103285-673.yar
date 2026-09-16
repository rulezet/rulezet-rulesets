rule Virus_Hijack_Trojan_GenericKDZ_103285_673 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_673.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "925c25bfbe8ae0f59036de087b88e91afaaf4c2f763660b264dd4631e30004e8"

  strings:
    $s1 = "&\\Oracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}