rule Methodology_Mutation_StackPush_Common_PE_Strings {
  meta:
    author = "Stairwell"
    description = "Searching for PE files with mutations of odd, rare, or interesting string equities. Here we look for strings from common PE strings, DLLs and functions in type 2 stack strings form, where the string pushed onto the stack 4 bytes at a time using PUSH 0x68, appearing in reverse four byte chunk order, where the PUSH which shows up as an ASCII letter h."
    hash = "ee42ddacbd202008bcc1312e548e1d9ac670dd3d86c999606a3a01d464a2a330"
  strings:
    $ThisprogramcannotberuninDOSmode_stackpush = "hdehS mohn DOhun ihbe rhnot h canhgramh prohThis" nocase
    $ThisprogrammustberununderWin32_stackpush = "hin32her Wh undh runht beh mushgramh prohThis" nocase
    $abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_stackpush = "h89h4567h0123hWXYZhSTUVhOPQRhKLMNhGHIJhCDEFhyzABhuvwxhqrsthmnophijklhefghhabcd" nocase
    $ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_stackpush = "h6789h2345hYZ01hUVWXhQRSThMNOPhIJKLhEFGHhABCD" nocase
    $ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_stackpush_2 = "h89+/h4567h0123hwxyzhstuvhopqrhklmnhghijhcdefhYZabhUVWXhQRSThMNOPhIJKLhEFGHhABCD" nocase
    $0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_stackpush = "hyz+/huvwxhqrsthmnophijklhefghhabcdhWXYZhSTUVhOPQRhKLMNhGHIJhCDEFh89ABh4567h0123" nocase
    $KERNEL32dll_stackpush = "h.dllhEL32hKERN" nocase
    $Kernel32dll_stackpush = "h.dllhel32hKern" nocase
    $kernel32dll_stackpush = "h.dllhel32hkern" nocase
    $msvcrtdll_stackpush = "hllhrt.dhmsvc" nocase
    $VCRUNTIME140dll_stackpush = "h.dllhE140hNTIMhVCRU" nocase
    $IsDebuggerPresent_stackpush = "hthesenherPrhbugghIsDe" nocase
    $RaiseException_stackpush = "honheptiheExchRais" nocase
    $MultiByteToWideChar_stackpush = "hharhideCheToWhiBythMult" nocase
    $WideCharToMultiByte_stackpush = "hytehltiBhToMuhCharhWide" nocase
    $UnhandledExceptionFilter_stackpush = "hlterhonFiheptihdExchndlehUnha" nocase
    $SetUnhandledExceptionFilter_stackpush = "hterhnFilhptiohExcehdledhnhanhSetU" nocase
    $GetCurrentProcess_stackpush = "hshoceshntPrhurrehGetC" nocase
    $TerminateProcess_stackpush = "hcessheProhinathTerm" nocase
    $IsProcessorFeaturePresent_stackpush = "hthesenhrePrheatuhsorFhoceshIsPr" nocase
    $QueryPerformanceCounter_stackpush = "hterhCounhancehformhyPerhQuer" nocase
    $GetCurrentProcessId_stackpush = "hsIdhoceshntPrhurrehGetC" nocase
    $GetSystemTimeAsFileTime_stackpush = "himehileTheAsFhmTimhystehGetS" nocase
    $InitializeSListHead_stackpush = "headhistHhzeSLhialihInit" nocase
    $GetStartupInfoW_stackpush = "hfoWhupInhtarthGetS" nocase
    $GetModuleHandleW_stackpush = "hdleWheHanhodulhGetM" nocase
    $GetLastError_stackpush = "hrrorhastEhGetL" nocase
    $HeapAlloc_stackpush = "hchAllohHeap" nocase
    $HeapFree_stackpush = "hFreehHeap" nocase
    $GetProcessHeap_stackpush = "haphssHehrocehGetP" nocase
    $GetCurrentThreadId_stackpush = "hIdhreadhntThhurrehGetC" nocase
    $VirtualQuery_stackpush = "hueryhualQhVirt" nocase
    $VirtualAlloc_stackpush = "hllochualAhVirt" nocase
    $FreeLibrary_stackpush = "haryhLibrhFree" nocase
    $GetProcAddress_stackpush = "hsshddrehrocAhGetP" nocase
    $xmlversion10encodingUTF8standaloneyes_stackpush = "hes'he='yhalonhtandh8' shUTF-hng='hcodih' enh'1.0hion=hvershxml " nocase
    $assemblyxmlnsurnschemasmicrosoftcomasmv1manifestVersion10_stackpush = "h>h1.0'hon='hersihestVhanifh1' mhsm.vhom:ahft-chrosoh-michemash:schh'urnhlns=hy xmhemblh<ass" nocase
    $trustInfoxmlnsurnschemasmicrosoftcomasmv3_stackpush = "hv3\">hasm.hcom:hoft-hcroshs-mihhemahn:sch=\"urhmlnshfo xhstInh<tru" nocase
    $security_stackpush = "hy>hurith<sec" nocase
    $requestedPrivileges_stackpush = "h>hegeshivilhedPrhuesth<req" nocase
    $requestedExecutionLevellevelasInvokeruiAccessfalse_stackpush = "h/>hse' h'falhess=hiAcchr' uhvokehasInhel='h levhevelhionLhecuthedExhuesth<req" nocase
    $requestedPrivileges_stackpush2 = "hs>hlegehrivihtedPhquesh</re" nocase
    $security_stackpush2 = "hty>hcurih</se" nocase
    $trustInfo_stackpush = "hnfo>hustIh</tr" nocase
    $assembly_stackpush = "hly>hsembh</as" nocase
    $ContentTypeapplicationoctetstream_stackpush = "hamhstrehtet-hn/ochatiohplich: aphTypehent-hCont" nocase
    $ContentLength_stackpush = "h%hth: hLenghent-hCont" nocase
    $MicrosoftBaseCryptographicProviderv10_stackpush = "h.0hr v1hvideh Prohphichograhrypthse Cht BahosofhMicr" nocase
  condition:
    filesize < 15MB and uint16be(0) == 0x4d5a and 1 of them
}