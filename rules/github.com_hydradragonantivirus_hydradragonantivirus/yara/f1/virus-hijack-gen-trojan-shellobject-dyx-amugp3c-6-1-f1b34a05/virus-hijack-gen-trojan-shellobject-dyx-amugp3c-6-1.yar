rule Virus_Hijack_Gen_Trojan_ShellObject_dyX_amUgp3c_6_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.dyX@amUgp3c_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b39a5e870ecc4b14df15bee9ed96bcdced834c9128df7d00ce8a44870644353f"

  strings:
    $x1  = "ExecutionPolicy Bypass -WindowStyle Hidden -NoExit -File \"" fullword wide
    $s2  = "Shell Command has been executed" fullword wide
    $s3  = "/c ping 1.1.1.1 -n 5 -w 5000 > Nul & Del \"" fullword wide
    $s4  = "Password Stealer has been executed" fullword wide
    $s5  = "!Host Process for Windows Services" fullword ascii
    $s6  = "KeyLogger is running !" fullword wide
    $s7  = "Set-MpPreference -DisableScriptScanning $true" fullword wide
    $s8  = "Script Has heen executed" fullword wide
    $s9  = "KeyLogger has been started" fullword wide
    $s10 = "Keylogger has been aborted" fullword wide
    $s11 = "Client has been elevated to admin" fullword wide
    $s12 = "Password Stelaer failed in collecting passwords" fullword wide
    $s13 = "&explorer /root,\"%CD%" fullword wide
    $s14 = "File has been uploaded and executed" fullword wide
    $s15 = "System did not find a .dat wallet" fullword wide
    $s16 = "KeyLogs file has been uploaded" fullword wide
    $s17 = "Custom Plugin has been executed" fullword wide
    $s18 = "Client Computer has been logged Off" fullword wide
    $s19 = "Set-MpPreference -DisableArchiveScanning $true" fullword wide
    $s20 = "HEAD / HTTP/1.1" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and 4 of them
}