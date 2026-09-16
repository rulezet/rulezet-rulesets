rule _Trojan_Hooker_Win32_Floxif_A_32_1_Virus_Infector_Trojan_Generic_295 {
  meta:
    description = "datamaliciousorder - from files Trojan.Hooker_Win32.Floxif.A_32_1.vir, Virus.Infector_Trojan.GenericKDZ.88432.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b1442f8fdeda8c8f7931dc26e4e64ef2712e0c9eedb9a5562bd87cd147455173"
    hash2       = "43173667ed5ba6d1539f4429373f0497aaee780a906808bb4a27f15acaf7b50b"

  strings:
    $s1 = "PCRat Update" fullword ascii
    $s2 = "RegQueryValueEx(Type)" fullword ascii
    $s3 = "RegSetValueEx(start)" fullword ascii
    $s4 = "Copyright ? 2009" fullword wide
    $s5 = "Device Protect Application" fullword wide

  condition:
    (uint16(0) == 0x5a4d and (all of them)
    ) or (all of them)
}