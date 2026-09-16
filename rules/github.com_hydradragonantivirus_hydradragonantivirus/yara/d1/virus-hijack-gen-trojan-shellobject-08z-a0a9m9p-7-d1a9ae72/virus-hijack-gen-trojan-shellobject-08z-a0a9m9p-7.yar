rule Virus_Hijack_Gen_Trojan_ShellObject_08Z_a0a9m9p_7 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.08Z@a0a9m9p_7.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f635f691454294bdb978aab4dde0c3d2395d0d249b844c7fed18d1f640c3a0f9"

  strings:
    $s1 = "7Software Assurance." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}