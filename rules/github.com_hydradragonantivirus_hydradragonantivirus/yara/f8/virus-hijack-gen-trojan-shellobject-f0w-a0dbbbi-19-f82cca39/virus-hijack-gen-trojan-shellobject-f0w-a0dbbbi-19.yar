rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_a0DbbBi_19 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@a0DbbBi_19.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4637ddeaa4f739f71ccd44711a25ad8cd5414eed64d3ea28a3277aaf75c120c0"

  strings:
    $s1 = "&dispute under this agreement to which Section B applies must be filed within one year in small claims" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}