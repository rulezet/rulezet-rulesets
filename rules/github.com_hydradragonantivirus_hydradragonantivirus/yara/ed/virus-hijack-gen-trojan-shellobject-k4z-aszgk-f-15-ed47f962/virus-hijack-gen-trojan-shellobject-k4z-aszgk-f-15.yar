rule Virus_Hijack_Gen_Trojan_ShellObject_k4Z_aSzGK_f_15 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.k4Z@aSzGK!f_15.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5972a37a50b7daa156d18d624255fc6cad8b0fb741db185b81a3840d27ff62f9"

  strings:
    $s1 = "/Oracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}