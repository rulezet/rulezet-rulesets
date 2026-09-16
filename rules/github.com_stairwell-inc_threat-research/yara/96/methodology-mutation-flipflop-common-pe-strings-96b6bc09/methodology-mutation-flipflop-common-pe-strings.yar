rule Methodology_Mutation_FLIPFLOP_Common_PE_Strings {
  meta:
    author = "Stairwell"
    description = "Searching for PE files with mutations of odd, rare, or interesting string equities. This string mutation takes its inspiration from APT29/CozyBear malware family called FLIPFLOP because it reads in a subfile but reverses every two bytes."
    hash = "ee42ddacbd202008bcc1312e548e1d9ac670dd3d86c999606a3a01d464a2a330"
  strings:
    $a0_ThisProgramCannot = "hTsip orrgmac naon tebr nui  nOD Somed" ascii nocase
    $a1_ThisProgramCannot_Win32 = "hTsip orrgmam su tebr nuu dnreW ni23" ascii nocase
    $a2_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 = "badcfehgjilknmporqtsvuxwzyBADCFEHGJILKNMPORQTSVUXWZY1032547698" ascii nocase
    $a3_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 = "BADCFEHGJILKNMPORQTSVUXWZY1032547698" ascii nocase
    $a4_alphabet_1 = "\"!$#&%('*),+.-0/21436587:9<;>=@?BADCFEHGJILKNMPORQTSVUXW" ascii nocase
    $a5_KERNEL32_dll = "EKNRLE23d.ll" ascii nocase
    $a6_msvcrt_dll = "smcvtrd.ll" ascii nocase
    $a7_VCRUNTIME140_dll = "CVURTNMI1E04d.ll" ascii nocase
    $a8_IsDebuggerPresent = "sIeDubggrerPsenet" ascii nocase
    $a9_RaiseException = "aRsiEecxpeitno" ascii nocase
    $a10_MultiByteToWideChar = "uMtlBityTeWodiCeahr" ascii nocase
    $a11_WideCharToMultiByte = "iWedhCraoTuMtlBitye" ascii nocase
    $a12_UnhandledExceptionFilter = "nUahdnelEdcxpeitnoiFtlre" ascii nocase
    $a13_SetUnhandledExceptionFilter = "eSUthnnalddexEectpoiFnlietr" ascii nocase
    $a14_GetCurrentProcess = "eGCtruertnrPcoses" ascii nocase
    $a15_TerminateProcess = "eTmrnitaPeorecss" ascii nocase
    $a16_IsProcessorFeaturePresent = "sIrPcoseosFraeuterrPsenet" ascii nocase
    $a17_QueryPerformanceCounter = "uQrePyreofmrnaecoCnuetr" ascii nocase
    $a18_GetCurrentProcessId = "eGCtruertnrPcoseIsd" ascii nocase
    $a19_GetSystemTimeAsFileTime = "eGStsyetTmmiAeFsliTemie" ascii nocase
    $a20_InitializeSListHead = "nItiaiilezLSsiHtaed" ascii nocase
    $a21_GetStartupInfoW = "eGStattrpunIofW" ascii nocase
    $a22_GetModuleHandleW = "eGMtdoluHenaldWe" ascii nocase
    $a23_GetLastError = "eGLtsaEtrrro" ascii nocase
    $a24_HeapAlloc = "eHpalAolc" ascii nocase
    $a25_HeapFree = "eHparFee" ascii nocase
    $a26_GetProcessHeap = "eGPtorecsseHpa" ascii nocase
    $a27_GetCurrentProcessId = "eGCtruertnrPcoseIsd" ascii nocase
    $a28_GetCurrentThreadId = "eGCtruertnhTerdadI" ascii nocase
    $a29_GetSystemTimeAsFileTime = "eGStsyetTmmiAeFsliTemie" ascii nocase
    $a30_VirtualQuery = "iVtrauQleuyr" ascii nocase
    $a31_FreeLibrary = "rFeeiLrbray" ascii nocase
    $a32_GetProcAddress = "eGPtorAcdderss" ascii nocase
    $a33_xml_ver = "mx levsroi=n1'0. 'neocidgn'=TU-F'8s atdnlano=ey'se'" ascii nocase
    $a34_xml_ver_manifest = "a<ssmelb ymxnl=su'nrs:hcmesam-ciorostfc-moa:msv.'1m nafiseVtreisno'=.1'0>" ascii nocase
    $a35_xml_trust_info = "t<urtsnIofx lmsn\"=ru:ncseham-simrcsofo-toc:msa.m3v>\"" ascii nocase
    $a36_security = "s<ceruti>y" ascii nocase
    $a37_requestedPrivileges = "r<qeeutsderPviligese>" ascii nocase
    $a38_requestedExecutionLevel = "r<qeeutsdexEcetuoiLnvelel vele'=sanIovek'ru Aiccse=sf'laes '>/" ascii nocase
    $a39_requestedPrivileges = "/<eruqseetPdiriveleg>s" ascii nocase
    $a40_ssecurity = "/<esuciryt>" ascii nocase
    $a41_trustInfo = "/<rtsuItfn>o" ascii nocase
    $a42_assembly = "/<saesbmyl>" ascii nocase
  condition:
    filesize < 15MB and uint16be(0) == 0x4d5a and 1 of them
}