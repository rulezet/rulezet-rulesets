rule Virus_Hijack_Trojan_GenericKDZ_105924_22_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_22_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b71178b174981fa53858dccb7c841f4e00dc5e64dc24188948417dd6b36e46b3"

  strings:
    $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii
    $s2 = "<description>Pickle driver PDialog component</description>" fullword ascii
    $s3 = "Windows Journal Note Writer Progress Dialog" fullword wide
    $s4 = "f0}\"/></application></compatibility><application xmlns=\"urn:schemas-microsoft-com:asm.v3\"><windowsSettings><dpiAware xmlns=\"" ascii

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and all of them
}