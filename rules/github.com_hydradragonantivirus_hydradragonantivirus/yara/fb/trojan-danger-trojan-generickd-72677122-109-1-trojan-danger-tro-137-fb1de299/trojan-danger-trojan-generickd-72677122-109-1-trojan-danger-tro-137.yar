rule _Trojan_Danger_Trojan_GenericKD_72677122_109_1_Trojan_Danger_Tro_137 {
  meta:
    description = "datamaliciousorder - from files Trojan.Danger_Trojan.GenericKD.72677122_109_1.vir, Trojan.Danger_Trojan.GenericKD.72677122_11_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "629716764f60db8d2f9a6a6d5dfe5c8467038f50eb354fe0778baa9c2eebcf49"
    hash2       = "158fa7a85bd36d871b7e7c2ac6efbf7c5ad67bd452deac2565c571b6266c6912"

  strings:
    $s1  = "'  not found in ProcessesToStart.txt" fullword wide
    $s2  = "ExecuteTcLaunch - Call SetWindowPos(Me.hwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOSIZE Or SWP_NOMOVE)" fullword wide
    $s3  = "ExecuteTcLaunch - Call SetWindowPos(Me.hwnd, HWND_BOTTOM, 0, 0, 0, 0, SWP_NOSIZE Or SWP_NOMOVE)" fullword wide
    $s4  = "[StopProcesses_Click] Shell: " fullword wide
    $s5  = "[StartDrivers] Starting Process: " fullword wide
    $s6  = "Process start failed:" fullword wide
    $s7  = "closing primary windows of process " fullword wide
    $s8  = "closing secondary windows of process " fullword wide
    $s9  = "Send WM_CLOSE to all windows of Process " fullword wide
    $s10 = "Please start broker process first." fullword wide
    $s11 = "Process is currently running. Should it be restarted?" fullword wide
    $s12 = "The process isn't running currently or wasn't started by Tc-Launch." fullword wide
    $s13 = "OpenServiceCodeWindow - MakeChild ServiceCode.hwnd, Me.hwnd, True" fullword wide
    $s14 = "[StartTaskMgr_Click] Starting Process: " fullword wide
    $s15 = "Starting Process: " fullword wide
    $s16 = "[Timer1_Timer] Starting Process: " fullword wide
    $s17 = "[StartSecondProcess] Starting Process: " fullword wide
    $s18 = "[StartTouchControl] Starting Process: " fullword wide
    $s19 = "[StartPrc] Starting Process: " fullword wide
    $s20 = "[StartUtilityProcess] Starting Process: " fullword wide

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}