rule _Trojan_Danger_Trojan_GenericKD_72853156_109_1_Trojan_Danger_Tro_543 {
  meta:
    description = "datamaliciousorder - from files Trojan.Danger_Trojan.GenericKD.72853156_109_1.vir, Trojan.Danger_Trojan.GenericKD.72853156_11_1.vir, Trojan.Danger_Trojan.GenericKD.72853156_12_1.vir, Trojan.Hooker_Win32.Floxif.A_31_1.vir, Virus.Delself_Gen.Variant.Downloader.19.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1172148af37f1a2ab91f421805f2d41c3954a16ab4a180e9ddd418a023c63811"
    hash2       = "d2d566655fb5efcc828e6cbac0443789374164659b8f95fe2d9346178fb02857"
    hash3       = "825cd31011b40f07e5bf1ee2fce5a08cc98fd8608f179fcb1e7dac6233b72b04"
    hash4       = "588e7f27c3b4f0d3dfb256dacbde2240534b3d81c81c0d68b2d448d06c1a1224"
    hash5       = "85f789270abe5eda5f79db50b383ac0762cebd34b98d721472d9ad1af849aab2"

  strings:
    $s1 = "Adobe? Flash? Player Installer/Uninstaller 10.1 r53" fullword wide
    $s2 = "Adobe? Flash? Player Installer/Uninstaller 10.1" fullword wide
    $s3 = "Copyright ? 1996-2010 Adobe, Inc." fullword wide
    $s4 = "Adobe? Flash? Player" fullword wide
    $s5 = "Flash? Player Installer/Uninstaller" fullword wide

  condition:
    (uint16(0) == 0x5a4d and (all of them)
    ) or (all of them)
}