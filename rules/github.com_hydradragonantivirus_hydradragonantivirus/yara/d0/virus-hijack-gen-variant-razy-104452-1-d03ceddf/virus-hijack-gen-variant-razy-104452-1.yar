rule Virus_Hijack_Gen_Variant_Razy_104452_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Variant.Razy.104452_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b42aa669506abe27c70aa835644f238138f85f68323a6ac5e6dca1a3e62a3aed"

  strings:
    $s1 = "jointuress" fullword wide
    $s2 = "wheelrace" fullword wide
    $s3 = "griffonage" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}