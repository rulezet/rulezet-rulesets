rule Trojan_Hooker__Win32_Floxif_A {
  meta:
    description = "datamaliciousorder - file Trojan.Hooker _Win32.Floxif.A.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c5e684ea617ad603f8a9b045684d2d4168f762e79712dd75489e4d517be7c842"

  strings:
    $s1 = "@ This" fullword ascii
    $s2 = "   <description>Application description here</description>" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}