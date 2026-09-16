rule Virus_Hijack_Trojan_Agent_DQQO_140 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_140.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "395aa9e7f80eba74b9d562ff31d716edb4c6e7342a31f6e500060697a37fbda2"

  strings:
    $s1 = "sIRE_OLSA_V120103_Def_V122304 Page 1 of 11 " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}