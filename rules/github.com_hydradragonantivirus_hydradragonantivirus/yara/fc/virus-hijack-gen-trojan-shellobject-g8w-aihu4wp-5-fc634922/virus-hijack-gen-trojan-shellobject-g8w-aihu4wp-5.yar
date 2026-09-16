rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aiHu4Wp_5 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aiHu4Wp_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "191dce49fe355e7c455506d50d370054496b8037da63b8b0f24dd446e2360847"

  strings:
    $s1 = "zWhat if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}