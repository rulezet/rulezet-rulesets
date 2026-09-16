rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_a0DbbBi_11 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@a0DbbBi_11.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6da55b91ad893cfc939bc0f79d9d188c78a0aa9d029e959f0e3da8633b266415"

  strings:
    $s1 = "v dispute under this agreement to which Section B applies must be filed within one year in small claims" fullword ascii
    $s2 = "sd&aWee" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}