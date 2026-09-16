rule Virus_Hijack_Gen_Trojan_ShellObject_fyY_a4uiSHo_23_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fyY@a4uiSHo_23_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cadf53ccec032c4cde019b082fbb406b8700b76fa50a2dffa6f5dad7a24f34b5"

  strings:
    $s1 = "Host@KA" fullword ascii
    $s2 = "5Request rejected because SOCKS server cannot connect.QRequest rejected because the client program and identd report different u" wide
    $s3 = "Server@wB" fullword ascii
    $s4 = "Exception o@" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}