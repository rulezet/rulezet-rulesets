rule Virus_Hijack_Gen_Trojan_ShellObject_f4W_aixDqOn_4_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f4W@aixDqOn_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "250db8abae6bdc1fd92ddac6ad2d24141ebe2dc2dc9a1a290307b4fe42afb50d"

  strings:
    $s1 = "11.0.61135.400 built by: RTMLDR" fullword wide
    $s2 = "Alles mark" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}