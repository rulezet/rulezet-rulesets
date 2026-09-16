rule VirusShareTrojanInject36111_14_1 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanInject36111_14_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "648ce8f90dc84afabd9354e946dc1d2a44073dd43a2828c5a42c1557e1ada8b2"

  strings:
    $s1  = "IMPORTANT INFORMATION!!!!" fullword wide
    $s2  = "Login : " fullword wide
    $s3  = "Mozilla Version: " fullword wide
    $s4  = "Opera Version: " fullword wide
    $s5  = "Password : " fullword wide
    $s6  = " - Send 0.02 BTC to: " fullword wide
    $s7  = " - Follow All Steps" fullword wide
    $s8  = ".NET Framework 4.6H" fullword ascii
    $s9  = "\\Opera Software\\Opera Stable\\Web Data" fullword wide
    $s10 = " 1.85 (Hash, version 2, native byte-order)" fullword wide
    $s11 = "; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" fullword wide
    $s12 = ") AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" fullword wide
    $s13 = "GetFormattedString from value type " fullword wide
    $s14 = "All your files are encrypted with Loki stealer:" fullword wide
    $s15 = "All your files are encrypted with Loki stealer: " fullword wide
    $s16 = "SELECT * FROM Win32_Product" fullword wide
    $s17 = "- Follow All Steps" fullword wide
    $s18 = "Key Not Found: {0}" fullword wide
    $s19 = "System Language : " fullword wide
    $s20 = "Browser Versions" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}