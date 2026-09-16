rule Virus_Hijack_Gen_Trojan_ShellObject_e8W_aycAujk_11 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8W@aycAujk_11.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0bd7ec4ba23c533f67a117e7d062d20ee0e5b6f138a16135e669fd74464251d4"

  strings:
    $s1 = "D[Workshop" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}