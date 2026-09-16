rule rule_Disable_TamperProtection_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Disable-TamperProtection' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Disable-TamperProtection"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Disable_TamperProtection_offensive_tool_keyword = " /v DisableAntiSpyware /t REG_DWORD /d 1 /f" nocase ascii wide
                        $string2_Disable_TamperProtection_offensive_tool_keyword = " /v DisableBehaviorMonitoring /t REG_DWORD /d 1 /f" nocase ascii wide
                        $string3_Disable_TamperProtection_offensive_tool_keyword = " /v DisableIOAVProtection /t REG_DWORD /d 1 /f" nocase ascii wide
                        $string4_Disable_TamperProtection_offensive_tool_keyword = " /v DisableOnAccessProtection /t REG_DWORD /d 1 /f" nocase ascii wide
                        $string5_Disable_TamperProtection_offensive_tool_keyword = " /v DisableScanOnRealtimeEnable /t REG_DWORD /d 1 /f" nocase ascii wide
                        $string6_Disable_TamperProtection_offensive_tool_keyword = /\/Disable\-TamperProtection\.git/ nocase ascii wide
                        $string7_Disable_TamperProtection_offensive_tool_keyword = "/v DisableAntiSpyware /t REG_DWORD /d 1 /f" nocase ascii wide
                        $string8_Disable_TamperProtection_offensive_tool_keyword = /\[\+\]\sWdFilter\sAltitude\sRegistry\skey\shas\sbeen\ssuccessfully\sdeleted/ nocase ascii wide
                        $string9_Disable_TamperProtection_offensive_tool_keyword = /\\Disable\-TamperProtection\\/ nocase ascii wide
                        $string10_Disable_TamperProtection_offensive_tool_keyword = "AlteredSecurity/Disable-TamperProtection" nocase ascii wide
                        $string11_Disable_TamperProtection_offensive_tool_keyword = "cb0b0fa30345d487f99dce16cb07ef0094938dbf7eedfe48e2a0ad7f2973a7bb" nocase ascii wide
                        $string12_Disable_TamperProtection_offensive_tool_keyword = /Disable\-TamperProtection\.cpp/ nocase ascii wide
                        $string13_Disable_TamperProtection_offensive_tool_keyword = /Disable\-TamperProtection\.exe/ nocase ascii wide
                        $string14_Disable_TamperProtection_offensive_tool_keyword = "E192C3DF-AE34-4E32-96BA-3D6B56EA76A4" nocase ascii wide
                        $string15_Disable_TamperProtection_offensive_tool_keyword = /reg\.exe\sadd\s\\\\"HKLM\\\\SOFTWARE\\\\Microsoft\\\\Windows\sDefender\\\\Features\\\\"\s\/v\sTamperProtection\s\/t\sREG_DWORD\s\/d\s4\s\/f/ nocase ascii wide
                        $string16_Disable_TamperProtection_offensive_tool_keyword = /reg\.exe\sdelete\s.{0,100}HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\Services\\\\WdFilter\\\\Instances\\\\WdFilter\sInstance.{0,100}\s\/v\sAltitude\s\/f/ nocase ascii wide
                        $string17_Disable_TamperProtection_offensive_tool_keyword = /reg\.exe\sdelete\s.{0,100}HKLM\\SYSTEM\\CurrentControlSet\\Services\\WdFilter\\Instances\\WdFilter\sInstance.{0,100}\s\/v\sAltitude\s\/f/ nocase ascii wide
                        $string18_Disable_TamperProtection_offensive_tool_keyword = "Spawning registry with TrustedInstaller privileges to delete WdFilter " nocase ascii wide
                        $string19_Disable_TamperProtection_offensive_tool_keyword = "Spawning registry with TrustedInstaller privileges to Disable 'DisableIOAVProtection' regkey" nocase ascii wide
                        $string20_Disable_TamperProtection_offensive_tool_keyword = "Spawning registry with TrustedInstaller privileges to Disable 'RealtimeMonitoring' regkey" nocase ascii wide
                        $string21_Disable_TamperProtection_offensive_tool_keyword = "Spawning registry with TrustedInstaller privileges to Enable 'TamperProtection' regkey" nocase ascii wide
                        $string22_Disable_TamperProtection_offensive_tool_keyword = /WDFilter\shas\sbeen\ssuccessfully\sunloaded\,\suse\soption\s2\sto\sdisable\sTamper\sProtection\./ nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or             uint16(0) == 0x457f or             uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or             uint32(0) == 0x504B0304 or             uint32(0) == 0xCAFEBABE or             uint32(0) == 0x4D534346 or             uint32(0) == 0xD0CF11E0 or             uint16(0) == 0x2321 or             uint16(0) == 0x3c3f         )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}