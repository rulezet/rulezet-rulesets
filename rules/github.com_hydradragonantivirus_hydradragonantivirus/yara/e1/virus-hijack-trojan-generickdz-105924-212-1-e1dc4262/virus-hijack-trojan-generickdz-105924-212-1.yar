rule Virus_Hijack_Trojan_GenericKDZ_105924_212_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_212_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "59c9b76209e4cab3e386bea54e292746d5be93dad86e47d86dd2c050e62fe084"

  strings:
    $x1 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\" xmlns:asmv3=\"urn:schemas-microsoft-com:asm.v3\"><t" ascii
    $s2 = "ttp://schemas.microsoft.com/SMI/2005/WindowsSettings\"><dpiAware>true</dpiAware></asmv3:windowsSettings></asmv3:application><ms_" ascii
    $s3 = "?readConfig@crashreport@@YA_NAEBV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@PEAV23@@Z" fullword ascii
    $s4 = "25f93a}\"></ms_compatibility:supportedOS></ms_compatibility:application></ms_compatibility:compatibility></assembly>PPADDINGXXPA" ascii
    $s5 = "The Document Foundation1 0" fullword ascii
    $s6 = "LibreOffice Build Team1" fullword ascii
    $s7 = " 2000-2020 by LibreOffice contributors. All rights reserved." fullword wide
    $s8 = "The Document Foundation10" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and all of them
}