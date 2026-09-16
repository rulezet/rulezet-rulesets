rule Virus_Autorun_Win32_Neshta_A_43 {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Win32.Neshta.A_43.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "af299eb6f9affa22d2b9018ffa61989fba53d804466689ef0909830b4ebe5390"

  strings:
    $x1  = "<assembly manifestVersion=\"1.0\" xmlns=\"urn:schemas-microsoft-com:asm.v1\"><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3" ascii
    $s2  = "Call to ShellExecute() for verb<" fullword wide
    $s3  = "Call to ShellExecuteEx() returned:" fullword wide
    $s4  = ".?AV<lambda_1>@?1??GetRunningProcessesMatching@ProcessUtil@@YA?AV?$vector@KV?$allocator@K@std@@@std@@ABV?$basic_string@_WU?$char" ascii
    $s5  = ".?AV<lambda_1>@?1??GetRunningProcessesMatching@ProcessUtil@@YA?AV?$vector@KV?$allocator@K@std@@@std@@ABV?$basic_string@_WU?$char" ascii
    $s6  = "ttp://schemas.microsoft.com/SMI/2005/WindowsSettings\"><dpiAware>true</dpiAware></asmv3:windowsSettings></asmv3:application><ms_" ascii
    $s7  = "URL Shortcut content:" fullword wide
    $s8  = "Last error=" fullword wide
    $s9  = "Directory:<" fullword wide
    $s10 = "Window Visibility:" fullword wide
    $s11 = "> returned:" fullword wide
    $s12 = "File that launches another file" fullword wide
    $s13 = "lity:application></ms_compatibility:compatibility></assembly>" fullword ascii
    $s14 = "vileges></security></trustInfo><asmv3:application xmlns:asmv3=\"urn:schemas-microsoft-com:asm.v3\"><asmv3:windowsSettings xmlns=" ascii
    $s15 = "Verb:<" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and 4 of them
}