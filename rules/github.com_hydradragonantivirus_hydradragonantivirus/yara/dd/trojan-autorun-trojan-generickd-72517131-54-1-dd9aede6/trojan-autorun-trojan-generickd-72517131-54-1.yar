rule Trojan_Autorun_Trojan_GenericKD_72517131_54_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.72517131_54_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ebf21e0dbfe977dc08c0cc5a1c63172a8f06ae1b3694a325b3ddf222eaec3bd0"

  strings:
    $s1 = "microsoft.com/office/backup. You may not distribute the backup co" fullword ascii
    $s2 = "e option to convert your trial rights to subscription or" fullword ascii
    $s3 = "a third party without restriction on the " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}