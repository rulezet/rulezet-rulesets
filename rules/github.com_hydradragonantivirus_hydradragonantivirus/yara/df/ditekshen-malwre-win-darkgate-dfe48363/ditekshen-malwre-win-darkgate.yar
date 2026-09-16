rule DITEKSHEN_MALWRE_Win_Darkgate: FILE {
  meta:
    description = "Detects DarkGate infostealer and coinminer"
    author      = "ditekSHen"
    id          = "4488e1e6-daac-5832-8326-3151c834daf1"
    date        = "2024-05-28"
    modified    = "2024-05-28"
    reference   = "https://github.com/ditekshen/detection"
    source_url  = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/malware.yar#L10765-L10789"
    license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
    logic_hash  = "805a04bbb3915d539e76927393384a2786c25490e8b9fc151d5b12415247578b"
    score       = 75
    quality     = 25
    tags        = "FILE"

  strings:
    $x1  = "SYSTEM Elevation: Completed, new DarkGate connection with SYSTEM privileges" ascii
    $x2  = "-u 0xDark" ascii
    $x3  = "DarkGate" ascii
    $x4  = "/c cmdkey /generic:\"127.0.0.2\" /user:\"SafeMode\" /pass:\"darkgatepassword0\"" ascii
    $s1  = "c:\\temp\\crash.txt" ascii
    $s2  = "/cookiesfile \"" ascii
    $s3  = "/c rmdir /s /q \"" ascii
    $s4  = "/c xcopy /E /I /Y \"%s\" \"%s\" && exit" ascii
    $s5  = "U_MemScan" ascii
    $s6  = "U_Google_AD" ascii
    $s7  = "untBotUtils" ascii
    $s8  = "____padoru____" ascii
    $s9  = "u_SysHook" ascii
    $s10 = "zLAxuU0kQKf3sWE7ePRO2imyg9GSpVoYC6rhlX48ZHnvjJDBNFtMd1I5acwbqT+=" ascii
    $s11 = "C:\\Windows\\System32\\ntdll.dll" fullword ascii
    $s12 = /(SYSTEM )?Elevation: (Cannot|I already|AT RAW|FAILURE)/ ascii
    $s13 = /Stub: (WARNING:|Configuration updated:|Global Ping Invoked)/ ascii

  condition:
    (uint16(0) == 0x5a4d and ((3 of ($x*)) or (2 of ($x*) and 3 of ($s*)) or (1 of ($x*) and 5 of ($s*)) or (6 of ($s*)))) or (10 of them)
}