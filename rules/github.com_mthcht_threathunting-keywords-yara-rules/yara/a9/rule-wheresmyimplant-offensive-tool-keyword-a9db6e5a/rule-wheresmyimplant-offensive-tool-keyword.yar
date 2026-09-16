rule rule_WheresMyImplant_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'WheresMyImplant' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WheresMyImplant"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_WheresMyImplant_offensive_tool_keyword = /\/C2\/Beacon\/.{0,100}\.cs/ nocase ascii wide
                        $string2_WheresMyImplant_offensive_tool_keyword = "/Inject/Dll/LoadDll" nocase ascii wide
                        $string3_WheresMyImplant_offensive_tool_keyword = /\/Inject\/PE\/.{0,100}\.cs/ nocase ascii wide
                        $string4_WheresMyImplant_offensive_tool_keyword = /\/Inject\/ShellCode\/.{0,100}\.cs/ nocase ascii wide
                        $string5_WheresMyImplant_offensive_tool_keyword = /\/KeyLogger\.cs/ nocase ascii wide
                        $string6_WheresMyImplant_offensive_tool_keyword = /\/Lateral\/SMB\.cs/ nocase ascii wide
                        $string7_WheresMyImplant_offensive_tool_keyword = /\/LoadDllRemote\.cs/ nocase ascii wide
                        $string8_WheresMyImplant_offensive_tool_keyword = /\/PE\/InjectPE\.cs/ nocase ascii wide
                        $string9_WheresMyImplant_offensive_tool_keyword = /\/Persistence\/InstallUtil\./ nocase ascii wide
                        $string10_WheresMyImplant_offensive_tool_keyword = "/WheresMyImplant/" nocase ascii wide
                        $string11_WheresMyImplant_offensive_tool_keyword = /\\WheresMyImplant/ nocase ascii wide
                        $string12_WheresMyImplant_offensive_tool_keyword = "0xbadjuju/WheresMyImplant" nocase ascii wide
                        $string13_WheresMyImplant_offensive_tool_keyword = /Collection\/MiniDumpWriteDump\./ nocase ascii wide
                        $string14_WheresMyImplant_offensive_tool_keyword = /Credentials\/CacheDump\./ nocase ascii wide
                        $string15_WheresMyImplant_offensive_tool_keyword = /Credentials\/LSASecrets\./ nocase ascii wide
                        $string16_WheresMyImplant_offensive_tool_keyword = "DumpBrowserHistory" nocase ascii wide
                        $string17_WheresMyImplant_offensive_tool_keyword = /Empire\.Agent\.Coms\./ nocase ascii wide
                        $string18_WheresMyImplant_offensive_tool_keyword = /Empire\.Agent\.cs/ nocase ascii wide
                        $string19_WheresMyImplant_offensive_tool_keyword = /Empire\.Agent\.Jobs\.cs/ nocase ascii wide
                        $string20_WheresMyImplant_offensive_tool_keyword = /Empire\.Agent\.Stager\./ nocase ascii wide
                        $string21_WheresMyImplant_offensive_tool_keyword = /InjectPERemote\.cs/ nocase ascii wide
                        $string22_WheresMyImplant_offensive_tool_keyword = "InjectPEWMIFSRemote" nocase ascii wide
                        $string23_WheresMyImplant_offensive_tool_keyword = /InjectShellCode\.cs/ nocase ascii wide
                        $string24_WheresMyImplant_offensive_tool_keyword = /InjectShellCodeRemote\.cs/ nocase ascii wide
                        $string25_WheresMyImplant_offensive_tool_keyword = "InjectShellCodeWMIFSB64" nocase ascii wide
                        $string26_WheresMyImplant_offensive_tool_keyword = /Lateral\/DCom\.cs/ nocase ascii wide
                        $string27_WheresMyImplant_offensive_tool_keyword = /Lateral\/PSExec\.cs/ nocase ascii wide
                        $string28_WheresMyImplant_offensive_tool_keyword = /Lateral\/SMBClient\.cs/ nocase ascii wide
                        $string29_WheresMyImplant_offensive_tool_keyword = /Lateral\/SMBClientDelete\.cs/ nocase ascii wide
                        $string30_WheresMyImplant_offensive_tool_keyword = /Lateral\/SMBClientGet\.cs/ nocase ascii wide
                        $string31_WheresMyImplant_offensive_tool_keyword = /Lateral\/SMBClientPut\.cs/ nocase ascii wide
                        $string32_WheresMyImplant_offensive_tool_keyword = /Lateral\/WMIExec\.cs/ nocase ascii wide
                        $string33_WheresMyImplant_offensive_tool_keyword = "namespace WheresMyImplant" nocase ascii wide
                        $string34_WheresMyImplant_offensive_tool_keyword = "Persistence/InstallWMI" nocase ascii wide
                        $string35_WheresMyImplant_offensive_tool_keyword = "PTHSMBClientDelete" nocase ascii wide
                        $string36_WheresMyImplant_offensive_tool_keyword = "PTHSMBClientGet" nocase ascii wide
                        $string37_WheresMyImplant_offensive_tool_keyword = "PTHSMBClientList" nocase ascii wide
                        $string38_WheresMyImplant_offensive_tool_keyword = "PTHSMBClientPut" nocase ascii wide
                        $string39_WheresMyImplant_offensive_tool_keyword = "PTHSMBExec" nocase ascii wide
                        $string40_WheresMyImplant_offensive_tool_keyword = "PTHWMIExec" nocase ascii wide
                        $string41_WheresMyImplant_offensive_tool_keyword = /root\\cimv2\:Win32_Implant/ nocase ascii wide
                        $string42_WheresMyImplant_offensive_tool_keyword = "StartWebServiceBeacon" nocase ascii wide
                        $string43_WheresMyImplant_offensive_tool_keyword = /WheresMyImplant\.cs/ nocase ascii wide
                        $string44_WheresMyImplant_offensive_tool_keyword = /WheresMyImplant\.git/ nocase ascii wide
                        $string45_WheresMyImplant_offensive_tool_keyword = /WheresMyImplant\.sln/ nocase ascii wide
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