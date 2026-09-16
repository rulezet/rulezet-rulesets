rule Virus_Hijack_Gen_Trojan_ShellObject_g8X_aiHu4Wp_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8X@aiHu4Wp_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b146591e82406ceb92c2eb490df018f45e084ac970d40365af0bb626e5b87bc7"

  strings:
    $s1 = "&sWhat if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}