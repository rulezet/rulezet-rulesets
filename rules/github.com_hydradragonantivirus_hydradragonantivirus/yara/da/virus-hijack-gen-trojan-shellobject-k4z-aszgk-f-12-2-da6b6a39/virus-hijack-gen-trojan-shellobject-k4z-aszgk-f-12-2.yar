rule Virus_Hijack_Gen_Trojan_ShellObject_k4Z_aSzGK_f_12_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.k4Z@aSzGK!f_12_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e5130c62f39e4a596dd8d82b4362a14885dc603de6b0b608317ddff7ecf8d30d"

  strings:
    $s1 = "4.7.2558.0 built by: NET471REL1" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}