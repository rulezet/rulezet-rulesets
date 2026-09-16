rule _Trojan_Sysbot_Win32_Sality_3_Virus_Hijack_GenPack_Backdoor_Hang_380 {
  meta:
    description = "datamaliciousorder - from files Trojan.Sysbot_Win32.Sality.3.vir, Virus.Hijack_GenPack.Backdoor.Hangup.B_469_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9517d49a8422edd7a5306c6438423042f9fb8ebbac9f46af771244bd329c6b50"
    hash2       = "6e591e844645cb69cabdade3ddd5ffabe9fd78527dc0bdc82c7ec42ab0ab9ccb"

  strings:
    $s1  = ".?AVTaskRunner@base@@" fullword ascii
    $s2  = "Check failed: !strchr(name, '\"'). " fullword ascii
    $s3  = ".?AVSingleThreadTaskRunner@base@@" fullword ascii
    $s4  = ".?AVSequencedTaskRunner@base@@" fullword ascii
    $s5  = ".?AV?$RefCountedThreadSafe@VTaskRunner@base@@UTaskRunnerTraits@2@@base@@" fullword ascii
    $s6  = "base::MessageLoopProxyImpl::OnDestruct" fullword ascii
    $s7  = ".?AVMessageLoopProxy@base@@" fullword ascii
    $s8  = "Check failed: !g_category_enabled[g_category_already_shutdown]. " fullword ascii
    $s9  = "Check failed: g_category_index < TRACE_EVENT_MAX_CATEGORIES. " fullword ascii
    $s10 = "Check failed: !g_category_enabled[new_index]. " fullword ascii
    $s11 = "must increase TRACE_EVENT_MAX_CATEGORIES" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}