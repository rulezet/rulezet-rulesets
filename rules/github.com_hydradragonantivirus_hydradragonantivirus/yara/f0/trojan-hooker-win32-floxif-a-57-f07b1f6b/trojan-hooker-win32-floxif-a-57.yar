rule Trojan_Hooker_Win32_Floxif_A_57 {
  meta:
    description = "datamaliciousorder - file Trojan.Hooker_Win32.Floxif.A_57.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e9f6598814fe37ce940ff4c4c5ce15acea481df2d1d717717c32882332d608d1"

  strings:
    $x1 = "RunProgram=\"forcenowait:hidcon:\\\"reg.exe\\\" add \\\"HKCU\\Software\\Yamicsoft\\Windows Manager\\\" /f /v \\\"Licence Email" ascii
    $x2 = "RunProgram=\"forcenowait:hidcon:\\\"reg.exe\\\" add \\\"HKCU\\Software\\Yamicsoft\\Windows Manager\\\" /f /v \\\"Licence Email" ascii
    $s3 = "1.6.0 develop [x86] " fullword ascii
    $s4 = "1.6.0 develop [x86] build 2712 (December 30, 2012)" fullword ascii
    $s5 = "@Deflate" fullword wide
    $s6 = "7z Setup SFX (x86)" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and all of them
}