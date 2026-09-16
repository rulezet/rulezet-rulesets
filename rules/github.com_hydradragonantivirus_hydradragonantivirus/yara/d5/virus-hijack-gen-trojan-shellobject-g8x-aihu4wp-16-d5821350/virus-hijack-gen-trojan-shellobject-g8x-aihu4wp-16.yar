rule Virus_Hijack_Gen_Trojan_ShellObject_g8X_aiHu4Wp_16 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8X@aiHu4Wp_16.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e1259a3170fa465d63b20f37a5938a0d9e2fe96b057ecdbe099a04e8c8aadbf0"

  strings:
    $s1 = "ZRWhat if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}