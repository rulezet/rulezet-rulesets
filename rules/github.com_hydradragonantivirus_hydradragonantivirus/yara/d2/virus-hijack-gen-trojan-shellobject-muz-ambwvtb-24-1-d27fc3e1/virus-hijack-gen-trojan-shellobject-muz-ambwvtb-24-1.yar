rule Virus_Hijack_Gen_Trojan_ShellObject_MuZ_amBwvTb_24_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.MuZ@amBwvTb_24_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "24d6bdcc1fd603ed16d96146e9dd9c3c876c19f70a0b262de431e5c333b43d49"

  strings:
    $s1 = " balance" fullword wide
    $s2 = "<Module>{269DA541-300F-4878-9F3D-F4C3C95E0C76}" fullword ascii
    $s3 = "exact " fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}