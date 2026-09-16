rule Virus_Hijack_Trojan_GenericKDZ_105924_14_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_14_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "de5867fbc85c4f2cd210f60d565c99ab039f0be41c0ec6c7729d795d0ff15ecf"

  strings:
    $x1  = "WSARecvWSASendabortedalt -> any -> connectconsolecpuproffloat32float64forcegcinvalidnop -> readdirsignal uintptrunknownwriteat i" ascii
    $x2  = "VirtualUnlockWTSFreeMemoryWriteConsoleWbad map statedalTLDpSugct?debugCall2048empty integerexchange fullgethostbynamegetservbyna" ascii
    $x3  = "invalid network interface nameinvalid pointer found on stacknotetsleep - waitm out of syncprotocol wrong type for socketreflect:" ascii
    $x4  = "mstartbad sequence numberbad value for fielddevice not a streamdirectory not emptydisk quota exceededdodeltimer: wrong Pfile alr" ascii
    $x5  = "file descriptor in bad statefindrunnable: netpoll with pfound pointer to free objectgcBgMarkWorker: mode not setgcstopm: negativ" ascii
    $x6  = "lock: lock countslice bounds out of rangesocket type not supportedstartm: p has runnable gsstoplockedm: not runnableunexpected k" ascii
    $x7  = "bad defer entry in panicbypassed recovery failedcan't scan our own stackconnection reset by peerdouble traceGCSweepStartfloating" ascii
    $x8  = "garbage collection scangcDrain phase incorrectgo with non-empty frameindex out of range [%x]interrupted system callinvalid escap" ascii
    $x9  = "s !=  ->  as  is  on +Inf-Inf3125ACDTACSTAEDTAESTAKDTAKSTAWSTAhomAtoiCESTChamDashEESTGOGCJulyJuneLEAFLisuMiaoModiNZDTNZSTNewaSAS" ascii
    $s10 = "ndard TimeTasmania Standard TimeWSAGetOverlappedResultWaitForMultipleObjectsaddress already in useadvapi32.dll not foundargument" ascii
    $s11 = "unlock: lock countsigsend: inconsistent statestack size not a power of 2startm: negative nmspinningstopTheWorld: holding locksti" ascii
    $s12 = "fractional secondg already scannedglobalAlloc.mutexinteger too largeinvalid bit size locked m0 woke upmark - bad statusmarkBits " ascii
    $s13 = "chan<-domainempty gopherhangupheaderkilledlistenminuteobjectpopcntreadatremoverenamerune1 secondselectsendtosocketstringstructsy" ascii
    $s14 = "atenation_MarkSetProcessShutdownParametersSetSecurityDescriptorControlcomparing uncomparable type crypto/rsa: decryption errorde" ascii
    $s15 = "movedindex out of rangeinput/output errormultihop attemptedno child processesno locks availablenon-minimal lengthoperation cance" ascii
    $s16 = "mDirectoryWGetTokenInformationHaiti Standard TimeIDS_Binary_OperatorIndia Standard TimeKhitan_Small_ScriptKorea Standard TimeLib" ascii
    $s17 = "ExWGetProcessMemoryInfoGetWindowsDirectoryWIDS_Trinary_OperatorIsrael Standard TimeJordan Standard TimeMeroitic_HieroglyphsProce" ascii
    $s18 = "reCoTaskMemFreeDeleteServiceEnumProcessesExitWindowsExFindFirstFileFindNextFileWFindResourceWFreeAddrInfoWGC sweep waitGetDriveT" ascii
    $s19 = "irep: already in goworkbuf is not emptyws2_32.dll not found of unexported method%s flag redefined: %s186264514923095703125931322" ascii
    $s20 = "itCodeProcessGetFileAttributesWGetModuleFileNameWGetModuleHandleExWGetSidSubAuthorityGetVolumePathNameWIran Standard TimeLookupA" ascii

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and all of them
}