rule Trojan_Hooker_Win32_Floxif_A_7 {
  meta:
    description = "datamaliciousorder - file Trojan.Hooker_Win32.Floxif.A_7.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a45c7bd1e1e9132b5d997f769e619283d3c12dc65810727452e93ed2132fe8ff"

  strings:
    $s1 = "POST  HTTP/1." fullword ascii
    $s2 = "IObit Information Technology1>0<" fullword ascii
    $s3 = "Copyright(c) 2005-2012" fullword wide
    $s4 = "n}PIZE" fullword ascii
    $s5 = "rICK 4" fullword ascii
    $s6 = "b?;HuRA" fullword ascii
    $s7 = "GabI{}" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}