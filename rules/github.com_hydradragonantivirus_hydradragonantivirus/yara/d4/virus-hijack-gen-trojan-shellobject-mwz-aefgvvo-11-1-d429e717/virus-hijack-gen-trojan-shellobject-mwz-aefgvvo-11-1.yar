rule Virus_Hijack_Gen_Trojan_ShellObject_mWZ_aeFgVVo_11_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.mWZ@aeFgVVo_11_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a369040116a283533a51d42254cd5124bf50b51ff4b1c0501afd22f3a10b59cc"

  strings:
    $s1 = "Window Security Startup.exe" fullword wide
    $s2 = "Window Security Startup" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}