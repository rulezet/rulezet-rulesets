rule _Virus_Hijack_Gen_Trojan_ShellObject_f8X_amgke_k_20_2_Virus_Hija_48 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.f8X@amgke!k_20_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8X@auLSMIo_16_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.fKX@aeBHSxm_4_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b00888b91be353d18e18c45d23c3967d666971a1f717bd02a9e9850292d73f39"
    hash2       = "49a22cf6e0b0bb0719ea71eaf4ddc13a1d9cfafe3de6dc8500db73676c71d120"
    hash3       = "8500714fc4386b92f5d03d7445c08af1e6b77d91fdc450fa950fbff55122dba6"

  strings:
    $s1  = "ARMDownloader:: BITS GetError returns error: " fullword wide
    $s2  = "MustElevate returns 0 - User already elevated" fullword wide
    $s3  = "Automatic preferences not provided with command line and not found in Registry - using default ARM preference AUTO_DOWNLOAD" fullword wide
    $s4  = "Skipping process: Name: explorer.exe, ID: %ld, file in use: %s" fullword wide
    $s5  = "Skipping process: Name: %s, ID: %ld, file in use: %s" fullword wide
    $s6  = "Skipping previously failed process" fullword wide
    $s7  = "Error BG_E_INVALID_AUTH_TARGET setting BG_AUTH_TARGET_PROXY, BG_AUTH_SCHEME_BASIC" fullword wide
    $s8  = "Error BG_E_INVALID_AUTH_SCHEME setting BG_AUTH_TARGET_PROXY, BG_AUTH_SCHEME_BASIC" fullword wide
    $s9  = "Error setting BG_AUTH_TARGET_PROXY, BG_AUTH_SCHEME_BASIC" fullword wide
    $s10 = "Error BG_E_INVALID_AUTH_TARGET setting BG_AUTH_TARGET_SERVER, BG_AUTH_SCHEME_BASIC" fullword wide
    $s11 = "Error BG_E_INVALID_AUTH_SCHEME setting BG_AUTH_TARGET_SERVER, BG_AUTH_SCHEME_BASIC" fullword wide
    $s12 = "Error setting BG_AUTH_TARGET_SERVER, BG_AUTH_SCHEME_BASIC" fullword wide
    $s13 = "EnumJobs all users - access denied" fullword wide
    $s14 = "AcroExch.Document.7\\shell - no value" fullword wide
    $s15 = "Will attempt to use legacy launcher - not found or not valid: " fullword wide
    $s16 = "User is not Administrator - Service is not allowed" fullword wide
    $s17 = "** Setting Error Condition: " fullword wide
    $s18 = "Port 443 Blocked: HTTPS:// BITS connection failed attempting HTTP:// connection" fullword wide
    $s19 = "Service Manager reported error after first attempt" fullword wide
    $s20 = "Not enough priviliges to run - returning 0" fullword wide

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}