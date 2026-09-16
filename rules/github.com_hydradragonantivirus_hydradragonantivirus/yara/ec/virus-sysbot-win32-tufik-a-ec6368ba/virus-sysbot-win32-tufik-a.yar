rule Virus_Sysbot_Win32_Tufik_A {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Win32.Tufik.A.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d50cfd816ccec2c1c0447f376c2e13bf23d4910d32341cb0b66877e2b5f8f318"

  strings:
    $s1 = ")cInternet Explorer 4.0 Desktop/Explorer " fullword wide
    $s2 = " Internet Explorer 4.0" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}