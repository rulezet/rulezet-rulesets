rule Trojan_Sysbot__Win32_Sality_3 {
  meta:
    description = "datamaliciousorder - file Trojan.Sysbot _Win32.Sality.3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d9e65475cd15106a24b49deb0747d1d61b53fa0dfefff93a28b12912b5bc68d8"

  strings:
    $s1 = "BAWd(b" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}