rule Virus_Hijack_Gen_Trojan_ShellObject_uuZ_amBwvTb_10 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.uuZ@amBwvTb_10.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f91a72afc192e1d5d4e859c68cdc24fbf0bd9fd23b44da1b8d333ae588e009c1"

  strings:
    $s1 = ",ANAl)(" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}