rule Virus_Hijack_Gen_Trojan_ShellObject_w8Z_aWEkp9f {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.w8Z@aWEkp9f.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c02a3cfa0a092be30671154ade2e67ee54d6e20c89f0fb538235000de9b01e3b"

  strings:
    $s1 = "{ZIRE_OLSA_V120103_Def_V122304 Page 7 of 11 " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}