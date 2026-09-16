rule Trojan_Danger_Trojan_GenericKD_67166905_387_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_387_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b98d5e7a627ab532741a06ebf76be20b9b9cd275bdd06143067bccf610598486"

  strings:
    $s1 = "LSoftware Assurance." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}