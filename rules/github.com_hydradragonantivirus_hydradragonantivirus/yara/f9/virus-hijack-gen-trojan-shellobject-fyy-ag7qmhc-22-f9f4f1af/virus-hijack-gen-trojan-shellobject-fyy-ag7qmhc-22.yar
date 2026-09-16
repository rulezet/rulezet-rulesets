rule Virus_Hijack_Gen_Trojan_ShellObject_fyY_aG7qmhc_22 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fyY@aG7qmhc_22.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2a83a1f9e7b7fb5ce2eb7306ac18d169e5e86226920b55b4d7e55c084a2547f1"

  strings:
    $s1 = "Host@FA" fullword ascii
    $s2 = "5Request rejected because SOCKS server cannot connect.QRequest rejected because the client program and identd report different u" wide
    $s3 = "Exception j@" fullword ascii
    $s4 = "Server@rB" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}