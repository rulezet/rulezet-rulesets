rule Virus_Hijack_Gen_Heur_Mint_Zard_30_28_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Heur.Mint.Zard.30_28_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6ea79cc84da0f40998399e493f5006620b2b9058eb673da7e190d945a2ce0d00"

  strings:
    $x1 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3" ascii
    $s2 = "ZwReadFileInformation with unsupported class " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and all of them
}