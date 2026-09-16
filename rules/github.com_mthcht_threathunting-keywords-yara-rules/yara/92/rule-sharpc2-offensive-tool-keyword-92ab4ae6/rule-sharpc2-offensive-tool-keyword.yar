rule rule_SharpC2_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharpC2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpC2"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SharpC2_offensive_tool_keyword = /\sPayloadType\.BIND_TCP/ nocase ascii wide
                        $string2_SharpC2_offensive_tool_keyword = " SharpC2" nocase ascii wide
                        $string3_SharpC2_offensive_tool_keyword = /\/C2Frame\./ nocase ascii wide
                        $string4_SharpC2_offensive_tool_keyword = "/C2Profiles/" nocase ascii wide
                        $string5_SharpC2_offensive_tool_keyword = /\/Client\/Commands\/Enumeration\.yaml/ nocase ascii wide
                        $string6_SharpC2_offensive_tool_keyword = /\/Client\/Commands\/Execution\.yaml/ nocase ascii wide
                        $string7_SharpC2_offensive_tool_keyword = /\/Client\/Commands\/Injection\.yaml/ nocase ascii wide
                        $string8_SharpC2_offensive_tool_keyword = /\/Client\/Commands\/Lateral\.yaml/ nocase ascii wide
                        $string9_SharpC2_offensive_tool_keyword = /\/Client\/Commands\/Tokens\.yaml/ nocase ascii wide
                        $string10_SharpC2_offensive_tool_keyword = /\/Client\/Pages\/Drones\.razor/ nocase ascii wide
                        $string11_SharpC2_offensive_tool_keyword = /\/Client\/Pages\/Payloads\.razor/ nocase ascii wide
                        $string12_SharpC2_offensive_tool_keyword = /\/Client\/Pages\/Pivots\.razor/ nocase ascii wide
                        $string13_SharpC2_offensive_tool_keyword = /\/Drones\/SleepDialogue\.razor/ nocase ascii wide
                        $string14_SharpC2_offensive_tool_keyword = "/ExeStager/" nocase ascii wide
                        $string15_SharpC2_offensive_tool_keyword = "/ExternalC2/" nocase ascii wide
                        $string16_SharpC2_offensive_tool_keyword = /\/IPayloadService\./ nocase ascii wide
                        $string17_SharpC2_offensive_tool_keyword = /\/PeerToPeerService\./ nocase ascii wide
                        $string18_SharpC2_offensive_tool_keyword = "/SharpC2" nocase ascii wide
                        $string19_SharpC2_offensive_tool_keyword = /\/stager\.ps1/ nocase ascii wide
                        $string20_SharpC2_offensive_tool_keyword = /\/teamserver\-linux\.tar\.gz/
                        $string21_SharpC2_offensive_tool_keyword = /\/teamserver\-win\.zip/ nocase ascii wide
                        $string22_SharpC2_offensive_tool_keyword = /\\SharpC2/ nocase ascii wide
                        $string23_SharpC2_offensive_tool_keyword = /\\stager\.ps1/ nocase ascii wide
                        $string24_SharpC2_offensive_tool_keyword = /\\teamserver\-win\.zip/ nocase ascii wide
                        $string25_SharpC2_offensive_tool_keyword = /192\.168\.1\.229\sPassw0rd\!/ nocase ascii wide
                        $string26_SharpC2_offensive_tool_keyword = "50050/SharpC2" nocase ascii wide
                        $string27_SharpC2_offensive_tool_keyword = "5E8106A6F89B053ED91C723D5D4CAE3FFC15F1CE" nocase ascii wide
                        $string28_SharpC2_offensive_tool_keyword = "87904247-C363-4F12-A13A-3DA484913F9E" nocase ascii wide
                        $string29_SharpC2_offensive_tool_keyword = "91EA50CD-E8DF-4EDF-A765-75354643BD0D" nocase ascii wide
                        $string30_SharpC2_offensive_tool_keyword = /C2ProfileResponse\.cs/ nocase ascii wide
                        $string31_SharpC2_offensive_tool_keyword = /com\.rastamouse\./ nocase ascii wide
                        $string32_SharpC2_offensive_tool_keyword = /Commands\/DcomCommand\./ nocase ascii wide
                        $string33_SharpC2_offensive_tool_keyword = /Commands\/DroneCommand\./ nocase ascii wide
                        $string34_SharpC2_offensive_tool_keyword = /Commands\/ExecuteAssembly\./ nocase ascii wide
                        $string35_SharpC2_offensive_tool_keyword = /Commands\/KillProcess\./ nocase ascii wide
                        $string36_SharpC2_offensive_tool_keyword = /Commands\/ListProcesses\./ nocase ascii wide
                        $string37_SharpC2_offensive_tool_keyword = /Commands\/PowerShellImport\./ nocase ascii wide
                        $string38_SharpC2_offensive_tool_keyword = /Commands\/PrintWorkingDirectory\./ nocase ascii wide
                        $string39_SharpC2_offensive_tool_keyword = /Commands\/PsExecCommand\./ nocase ascii wide
                        $string40_SharpC2_offensive_tool_keyword = /Commands\/RevToSelf\./ nocase ascii wide
                        $string41_SharpC2_offensive_tool_keyword = /Commands\/RunPe\./ nocase ascii wide
                        $string42_SharpC2_offensive_tool_keyword = /Commands\/SetSleep\./ nocase ascii wide
                        $string43_SharpC2_offensive_tool_keyword = /Commands\/Shell\./ nocase ascii wide
                        $string44_SharpC2_offensive_tool_keyword = /Commands\/ShInject\./ nocase ascii wide
                        $string45_SharpC2_offensive_tool_keyword = /Commands\/ShSpawn\./ nocase ascii wide
                        $string46_SharpC2_offensive_tool_keyword = /Commands\/StealToken\./ nocase ascii wide
                        $string47_SharpC2_offensive_tool_keyword = /Commands\/StopDrone\./ nocase ascii wide
                        $string48_SharpC2_offensive_tool_keyword = /Commands\/TakeScreenshot\./ nocase ascii wide
                        $string49_SharpC2_offensive_tool_keyword = /Commands\/WhoAmI\./ nocase ascii wide
                        $string50_SharpC2_offensive_tool_keyword = /Commands\/WinRmCommand\./ nocase ascii wide
                        $string51_SharpC2_offensive_tool_keyword = /Commands\/WmiCommand\./ nocase ascii wide
                        $string52_SharpC2_offensive_tool_keyword = "DE7B9E6B-F73B-4573-A4C7-D314B528CFCB" nocase ascii wide
                        $string53_SharpC2_offensive_tool_keyword = /demo\-client\.exe\s/ nocase ascii wide
                        $string54_SharpC2_offensive_tool_keyword = /demo\-controller\.exe\s/ nocase ascii wide
                        $string55_SharpC2_offensive_tool_keyword = /exe_stager\.exe/ nocase ascii wide
                        $string56_SharpC2_offensive_tool_keyword = /ExeStager\.csproj/ nocase ascii wide
                        $string57_SharpC2_offensive_tool_keyword = /ExternalC2\.Net/ nocase ascii wide
                        $string58_SharpC2_offensive_tool_keyword = /ExternalC2\.Net\./ nocase ascii wide
                        $string59_SharpC2_offensive_tool_keyword = /ExternalC2\\/ nocase ascii wide
                        $string60_SharpC2_offensive_tool_keyword = "GenerateReverseTcpDrone" nocase ascii wide
                        $string61_SharpC2_offensive_tool_keyword = /http.{0,100}127\.0\.0\.1\:50050/ nocase ascii wide
                        $string62_SharpC2_offensive_tool_keyword = /http.{0,100}localhost\:50050/ nocase ascii wide
                        $string63_SharpC2_offensive_tool_keyword = /IPeerToPeerService\./ nocase ascii wide
                        $string64_SharpC2_offensive_tool_keyword = /IReversePortForwardService\./ nocase ascii wide
                        $string65_SharpC2_offensive_tool_keyword = /PayloadFormat\.ASSEMBLY/ nocase ascii wide
                        $string66_SharpC2_offensive_tool_keyword = /PayloadFormat\.DLL/ nocase ascii wide
                        $string67_SharpC2_offensive_tool_keyword = /PayloadFormat\.EXE/ nocase ascii wide
                        $string68_SharpC2_offensive_tool_keyword = /PayloadFormat\.POWERSHELL/ nocase ascii wide
                        $string69_SharpC2_offensive_tool_keyword = /PayloadFormat\.SHELLCODE/ nocase ascii wide
                        $string70_SharpC2_offensive_tool_keyword = /PayloadFormat\.SVC_EXE/ nocase ascii wide
                        $string71_SharpC2_offensive_tool_keyword = /PayloadService\./ nocase ascii wide
                        $string72_SharpC2_offensive_tool_keyword = /PayloadType\.BIND_PIPE/ nocase ascii wide
                        $string73_SharpC2_offensive_tool_keyword = /PayloadType\.EXTERNAL/ nocase ascii wide
                        $string74_SharpC2_offensive_tool_keyword = /PayloadType\.HTTP/ nocase ascii wide
                        $string75_SharpC2_offensive_tool_keyword = /PayloadType\.REVERSE_TCP/ nocase ascii wide
                        $string76_SharpC2_offensive_tool_keyword = /PELoader\/PeLoader\./ nocase ascii wide
                        $string77_SharpC2_offensive_tool_keyword = "rasta-mouse/SharpC2" nocase ascii wide
                        $string78_SharpC2_offensive_tool_keyword = /Resources\/drone\.dll/ nocase ascii wide
                        $string79_SharpC2_offensive_tool_keyword = "SharpC2 " nocase ascii wide
                        $string80_SharpC2_offensive_tool_keyword = /SharpC2.{0,100}\.cs/ nocase ascii wide
                        $string81_SharpC2_offensive_tool_keyword = /SharpC2.{0,100}\.exe/ nocase ascii wide
                        $string82_SharpC2_offensive_tool_keyword = /sharpc2.{0,100}client\-windows\.zip/ nocase ascii wide
                        $string83_SharpC2_offensive_tool_keyword = /SharpC2\./ nocase ascii wide
                        $string84_SharpC2_offensive_tool_keyword = /SharpC2\.API/ nocase ascii wide
                        $string85_SharpC2_offensive_tool_keyword = "SharpC2Event" nocase ascii wide
                        $string86_SharpC2_offensive_tool_keyword = "SharpC2Hub" nocase ascii wide
                        $string87_SharpC2_offensive_tool_keyword = "SharpC2Webhook" nocase ascii wide
                        $string88_SharpC2_offensive_tool_keyword = /Stagers\\ExeStager\\/ nocase ascii wide
                        $string89_SharpC2_offensive_tool_keyword = /Stagers\\SvcStager\\/ nocase ascii wide
                        $string90_SharpC2_offensive_tool_keyword = /svc_stager\.exe/ nocase ascii wide
                        $string91_SharpC2_offensive_tool_keyword = /TeamServer\.C2Profiles/ nocase ascii wide
                        $string92_SharpC2_offensive_tool_keyword = "TeamServer/Filters/InjectionFilters" nocase ascii wide
                        $string93_SharpC2_offensive_tool_keyword = /TeamServer\/Pivots\/.{0,100}\./ nocase ascii wide
                        $string94_SharpC2_offensive_tool_keyword = /TeamServer\\TeamServer\./ nocase ascii wide
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