rule Virus_Hijack_Gen_Trojan_ShellObject_e8X_aian2n_33_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8X@aian2n_33_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "62db18b1b1d4ac66d198ecfbc1195dc13373fd29833c58bf71cfa4255679c578"

  strings:
    $s1 = " 2011 dotPDN LLC, Rick Brewster, and past contributors. All Rights Reserved." fullword wide
    $s2 = "\"Powered by SmartAssembly 6.8.0.121" fullword ascii
    $s3 = "Copyright Klenex 2021" fullword ascii
    $s4 = "ALEn[Q" fullword ascii
    $s5 = "q`mANd" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}