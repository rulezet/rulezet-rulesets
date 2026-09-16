rule Virus_Hijack_Gen_Trojan_ShellObject_k4Z_a8_cJFh_7 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.k4Z@a8!cJFh_7.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "777609ec3c2991bd17b04801d0e93e71d1517a9a2ed6117dcd1d18593c426353"

  strings:
    $s1 = "5Oracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}