rule Virus_Hijack_Gen_Trojan_ShellObject_juZ_aKo42Jj_9_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.juZ@aKo42Jj_9_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0a2f600b8fe66775e7be4f4aafd9dc2bbcec2fd481f69d3b6c32782cde89d129"

  strings:
    $s1 = "e!Sker" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}