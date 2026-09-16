rule Virus_Hijack_Trojan_GenericKDZ_103285_472 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_472.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2bfc21bd24075f39de7d198298d95f32af6ae733adeaadcea2f9329eebea1ef1"

  strings:
    $s1 = "aOracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}