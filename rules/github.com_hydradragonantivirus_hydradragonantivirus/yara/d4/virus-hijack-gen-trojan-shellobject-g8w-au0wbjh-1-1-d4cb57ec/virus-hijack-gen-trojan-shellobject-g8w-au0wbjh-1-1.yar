rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_au0WBJh_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@au0WBJh_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "93ef8557a80bff11080b36508bc81c97afefdd383999fd293697588af02700a2"

  strings:
    $s1 = "Hygroscope" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}