rule Virus_Hijack_Gen_Trojan_ShellObject_08Z_a0a9m9p_5 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.08Z@a0a9m9p_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e4b6a45ff21a6da148b496fcba8a73e3c59ad25fe7b9892843ed50ddf71d1a59"

  strings:
    $s1 = "|Software Assurance." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}