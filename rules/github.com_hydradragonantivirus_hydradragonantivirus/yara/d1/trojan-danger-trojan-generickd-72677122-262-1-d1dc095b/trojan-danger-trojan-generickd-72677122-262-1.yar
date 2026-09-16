rule Trojan_Danger_Trojan_GenericKD_72677122_262_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72677122_262_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4717d1bd8a59bdbb4632cb9e20d66d688b2bdab1f2e6fd2681c8ce39fdfb528e"

  strings:
    $s1  = "?Launch@SBTarget@lldb@@QAE?AVSBProcess@2@AAVSBListener@2@PAPBD1PBD222I_NAAVSBError@2@@Z" fullword ascii
    $s2  = "?Kill@SBProcess@lldb@@QAE?AVSBError@2@XZ" fullword ascii
    $s3  = "?Detach@SBProcess@lldb@@QAE?AVSBError@2@_N@Z" fullword ascii
    $s4  = "?Continue@SBProcess@lldb@@QAE?AVSBError@2@XZ" fullword ascii
    $s5  = "?Initialize@SBInputReader@lldb@@QAE?AVSBError@2@AAVSBDebugger@2@P6AKPAXPAV12@W4InputReaderAction@2@PBDK@Z1W4InputReaderGranulari" ascii
    $s6  = "?Initialize@SBInputReader@lldb@@QAE?AVSBError@2@AAVSBDebugger@2@P6AKPAXPAV12@W4InputReaderAction@2@PBDK@Z1W4InputReaderGranulari" ascii
    $s7  = "?Success@SBError@lldb@@QBE_NXZ" fullword ascii
    $s8  = "?Watch@SBValue@lldb@@QAE?AVSBWatchpoint@2@_N00AAVSBError@2@@Z" fullword ascii
    $s9  = "?Fail@SBError@lldb@@QBE_NXZ" fullword ascii
    $s10 = "?Suspend@SBThread@lldb@@QAE_NXZ" fullword ascii
    $s11 = "?Resume@SBThread@lldb@@QAE_NXZ" fullword ascii
    $s12 = " WSA error: " fullword ascii
    $s13 = " NSBundle summary provider" fullword ascii
    $s14 = " NSURL summary provider" fullword ascii
    $s15 = "?Clear@SBStream@lldb@@QAEXXZ" fullword ascii
    $s16 = "?Cast@SBValue@lldb@@QAE?AV12@VSBType@2@@Z" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}