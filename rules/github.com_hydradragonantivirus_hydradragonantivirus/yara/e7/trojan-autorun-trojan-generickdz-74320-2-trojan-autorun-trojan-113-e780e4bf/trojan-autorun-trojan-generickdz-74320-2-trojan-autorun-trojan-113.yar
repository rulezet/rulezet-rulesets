import "pe"
rule _Trojan_Autorun_Trojan_GenericKDZ_74320_2_Trojan_Autorun_Trojan__113 {
  meta:
    description = "datamaliciousorder - from files Trojan.Autorun_Trojan.GenericKDZ.74320_2.vir, Trojan.Autorun_Trojan.GenericKDZ.74320_27.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cfdbab85abc6359dd930a51758e8a12ad261b2f7d8b9e119584fdc25fef00e19"
    hash2       = "86cb3a6e06c0faa5c1f55f737e49b3467ad2ffa1411668fe41883dad784015ae"

  strings:
    $x1  = "C:\\Users\\user\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu" fullword wide
    $s2  = "Launch Internet Explorer Browser.lnk" fullword ascii
    $s3  = "opera installer" fullword wide
    $s4  = "microsoft .net framework 4.5.2 setup_20151216_212237215.html" fullword wide
    $s5  = "Sharing Configuration Manager" fullword wide
    $s6  = "Remote IPC" fullword wide
    $s7  = "jUser Pinned" fullword wide
    $s8  = "dummy://url/" fullword wide
    $s9  = "rosoft\\Internet Explorer" fullword wide
    $s10 = "Start Menu Cache" fullword wide

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "d3cbd6e8f81da85f6bf0529e69de9251" and (1 of ($x*) and all of them)
    ) or (all of them)
}