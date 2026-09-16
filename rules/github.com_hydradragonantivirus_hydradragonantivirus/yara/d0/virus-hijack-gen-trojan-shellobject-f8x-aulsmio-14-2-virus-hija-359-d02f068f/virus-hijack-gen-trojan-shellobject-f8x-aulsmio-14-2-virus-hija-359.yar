rule _Virus_Hijack_Gen_Trojan_ShellObject_f8X_auLSMIo_14_2_Virus_Hija_359 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.f8X@auLSMIo_14_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8Y@aiYvnz_7_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8Y@aiYvnz_8_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8Y@aSZtDuk_11_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.fCY@aijlKSl_8_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.fKX@aeBHSxm_6_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e8c915ad781df337e261cdc99f3e468ecdf8695dbae199331224c8d9053d629f"
    hash2       = "d38ed19cfb2457a7b7ad16624740f7634a10d27be7b9f4d2bdcfa1cd81064139"
    hash3       = "7930967745fd6725e330572b310a4531d9a4064a5c5bf6dbeef19be0c0934370"
    hash4       = "b5448abc7a636d441e1eb18bfaa888c74c08af8d56ba0b27d2483ab5450bfc9f"
    hash5       = "0e539a4c280d3b5e62ba918ee31e2e53391bbe94ee0f89e5ab81712900c8cb06"
    hash6       = "f93cf777d77246b51bdb545a6e8bfbd99809e560c1d951161ea5ba348cdeec0a"

  strings:
    $s1  = "System Error: SystemParametersInfo failed" fullword wide
    $s2  = "System Error: Shell_NotifyIcon failed" fullword wide
    $s3  = "System Error: GetCursorPos failed" fullword wide
    $s4  = "System Error: GetCursorInfo failed" fullword wide
    $s5  = "System Error: GetMonitorInfo failed" fullword wide
    $s6  = "System Error: GetSystemMetrics failed" fullword wide
    $s7  = "Microsoft Office Sync Process Tooltip" fullword wide
    $s8  = "System Error: GetDeviceCaps failed" fullword wide
    $s9  = "System Error: DestroyIcon failed" fullword wide
    $s10 = "System Error: Failed to free RichEdit" fullword wide
    $s11 = "System Error: Failed to free MSPTLS" fullword wide
    $s12 = "System Error: Failed to free InstRez" fullword wide
    $s13 = "System Error: DeleteDC failed" fullword wide
    $s14 = "System Error: CreateWindowEx failed" fullword wide
    $s15 = "System Error: LoadImage failed" fullword wide
    $s16 = "System Error: AppendMenu failed" fullword wide
    $s17 = "System Error: SetMenuDefaultItem failed" fullword wide
    $s18 = "System Error: DestroyMenu failed" fullword wide
    $s19 = "System Error: SetTimer failed" fullword wide
    $s20 = "System Error: MonitorFromRect failed" fullword wide

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}