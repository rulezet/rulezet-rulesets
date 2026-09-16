rule Trojan_Autorun_Trojan_GenericKDZ_94847_270_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_270_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4af35d1d12f839d6ac78773033ebaee8a48172dd5dbe95446dcf39464a086407"

  strings:
    $s1 = "/C(tuTU" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}