rule Virus_Hijack_Gen_Trojan_ShellObject_iWZ_auBEZAc_14_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.iWZ@auBEZAc_14_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d26838760840fc21c3dff1218750f41334becff685e127c2679cffe576229e7b"

  strings:
    $s1 = "Z>LAZY" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}