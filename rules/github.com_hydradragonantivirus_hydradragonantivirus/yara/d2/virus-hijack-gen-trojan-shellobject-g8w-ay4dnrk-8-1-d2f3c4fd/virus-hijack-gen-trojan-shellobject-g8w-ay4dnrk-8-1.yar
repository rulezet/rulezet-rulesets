rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_ay4DNrk_8_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@ay4DNrk_8_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ba17b6a8db403234d60cc7b62c3381abf1bc7ec7e380eca967e7a17b5057588d"

  strings:
    $s1 = "Xerotes" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}