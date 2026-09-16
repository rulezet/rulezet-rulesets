rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_a0DbbBi_21 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@a0DbbBi_21.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dd5ee9570e389bf228d258fde401651552eebf5c09de012de63f313efd6b71b4"

  strings:
    $s1 = "/dispute under this agreement to which Section B applies must be filed within one year in small claims" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}