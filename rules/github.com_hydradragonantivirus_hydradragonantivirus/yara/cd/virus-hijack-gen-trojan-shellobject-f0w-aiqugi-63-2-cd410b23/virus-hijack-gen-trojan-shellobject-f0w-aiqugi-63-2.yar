rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_63_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_63_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "da961e2ef259a6989f065c8ccc6197955ac58af48ab37a1db15602754790067a"

  strings:
    $s1 = "/E>ToUg*LZ" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}