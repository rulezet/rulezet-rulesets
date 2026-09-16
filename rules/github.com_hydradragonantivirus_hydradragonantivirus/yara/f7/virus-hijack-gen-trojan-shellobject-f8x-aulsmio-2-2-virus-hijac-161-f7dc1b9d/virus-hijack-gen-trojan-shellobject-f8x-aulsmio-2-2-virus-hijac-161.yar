rule _Virus_Hijack_Gen_Trojan_ShellObject_f8X_auLSMIo_2_2_Virus_Hijac_161 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.f8X@auLSMIo_2_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.fKX@aeBHSxm_7_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "838086ed8b4207c84b7c179a283d8cfe128e7e3c50a0073d96c26764f782742d"
    hash2       = "b12935f20c6bfcb2009d48462f248b15d7030a105694721bc8cdd57f4856ec59"

  strings:
    $s1  = "Subscription licensing service failed: %d" fullword wide
    $s2  = "Licensing: Error connecting to config service using identity for federation provider" fullword wide
    $s3  = "Error connecting to config service" fullword wide
    $s4  = "Attempting Activation" fullword wide
    $s5  = "Cache file doesn't exist - Creating empty version" fullword wide
    $s6  = "Failed to initialize service against endpoint" fullword wide
    $s7  = "Attempting to redirect for known error cases" fullword wide
    $s8  = "Attempting to redirect for ServiceUnavailable case" fullword wide
    $s9  = "Reporting Ols Error" fullword wide
    $s10 = "Reporting Service Error" fullword wide
    $s11 = "Number of subscription licenses found" fullword wide
    $s12 = "Exiting: SOAP Initialization Complete" fullword wide
    $s13 = "Adding client information to OLS header" fullword wide
    $s14 = "Error encountered calling WsAddCustomHeader()" fullword wide
    $s15 = "Another instance of the scheduled task is currently running." fullword wide
    $s16 = "Office 2016 Licensing Service" fullword wide
    $s17 = "Licensing: Initializing SOAP connection to OLS" fullword wide
    $s18 = "Service URL endpoint acquired" fullword wide
    $s19 = "Initializing service against endpoint" fullword wide
    $s20 = "Failed to extract server fault" fullword wide

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}