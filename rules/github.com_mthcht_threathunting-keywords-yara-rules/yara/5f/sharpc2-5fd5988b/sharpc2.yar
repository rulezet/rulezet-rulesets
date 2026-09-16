rule SharpC2
{
    meta:
        description = "Detection patterns for the tool 'SharpC2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpC2"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sPayloadType\.BIND_TCP/ nocase ascii wide
                        $string2 = " SharpC2" nocase ascii wide
                        $string3 = /\/C2Frame\./ nocase ascii wide
                        $string4 = "/C2Profiles/" nocase ascii wide
                        $string5 = /\/Client\/Commands\/Enumeration\.yaml/ nocase ascii wide
                        $string6 = /\/Client\/Commands\/Execution\.yaml/ nocase ascii wide
                        $string7 = /\/Client\/Commands\/Injection\.yaml/ nocase ascii wide
                        $string8 = /\/Client\/Commands\/Lateral\.yaml/ nocase ascii wide
                        $string9 = /\/Client\/Commands\/Tokens\.yaml/ nocase ascii wide
                        $string10 = /\/Client\/Pages\/Drones\.razor/ nocase ascii wide
                        $string11 = /\/Client\/Pages\/Payloads\.razor/ nocase ascii wide
                        $string12 = /\/Client\/Pages\/Pivots\.razor/ nocase ascii wide
                        $string13 = /\/Drones\/SleepDialogue\.razor/ nocase ascii wide
                        $string14 = "/ExeStager/" nocase ascii wide
                        $string15 = "/ExternalC2/" nocase ascii wide
                        $string16 = /\/IPayloadService\./ nocase ascii wide
                        $string17 = /\/PeerToPeerService\./ nocase ascii wide
                        $string18 = "/SharpC2" nocase ascii wide
                        $string19 = /\/stager\.ps1/ nocase ascii wide
                        $string20 = /\/teamserver\-linux\.tar\.gz/
                        $string21 = /\/teamserver\-win\.zip/ nocase ascii wide
                        $string22 = /\\SharpC2/ nocase ascii wide
                        $string23 = /\\stager\.ps1/ nocase ascii wide
                        $string24 = /\\teamserver\-win\.zip/ nocase ascii wide
                        $string25 = /192\.168\.1\.229\sPassw0rd\!/ nocase ascii wide
                        $string26 = "50050/SharpC2" nocase ascii wide
                        $string27 = "5E8106A6F89B053ED91C723D5D4CAE3FFC15F1CE" nocase ascii wide
                        $string28 = "87904247-C363-4F12-A13A-3DA484913F9E" nocase ascii wide
                        $string29 = "91EA50CD-E8DF-4EDF-A765-75354643BD0D" nocase ascii wide
                        $string30 = /C2ProfileResponse\.cs/ nocase ascii wide
                        $string31 = /com\.rastamouse\./ nocase ascii wide
                        $string32 = /Commands\/DcomCommand\./ nocase ascii wide
                        $string33 = /Commands\/DroneCommand\./ nocase ascii wide
                        $string34 = /Commands\/ExecuteAssembly\./ nocase ascii wide
                        $string35 = /Commands\/KillProcess\./ nocase ascii wide
                        $string36 = /Commands\/ListProcesses\./ nocase ascii wide
                        $string37 = /Commands\/PowerShellImport\./ nocase ascii wide
                        $string38 = /Commands\/PrintWorkingDirectory\./ nocase ascii wide
                        $string39 = /Commands\/PsExecCommand\./ nocase ascii wide
                        $string40 = /Commands\/RevToSelf\./ nocase ascii wide
                        $string41 = /Commands\/RunPe\./ nocase ascii wide
                        $string42 = /Commands\/SetSleep\./ nocase ascii wide
                        $string43 = /Commands\/Shell\./ nocase ascii wide
                        $string44 = /Commands\/ShInject\./ nocase ascii wide
                        $string45 = /Commands\/ShSpawn\./ nocase ascii wide
                        $string46 = /Commands\/StealToken\./ nocase ascii wide
                        $string47 = /Commands\/StopDrone\./ nocase ascii wide
                        $string48 = /Commands\/TakeScreenshot\./ nocase ascii wide
                        $string49 = /Commands\/WhoAmI\./ nocase ascii wide
                        $string50 = /Commands\/WinRmCommand\./ nocase ascii wide
                        $string51 = /Commands\/WmiCommand\./ nocase ascii wide
                        $string52 = "DE7B9E6B-F73B-4573-A4C7-D314B528CFCB" nocase ascii wide
                        $string53 = /demo\-client\.exe\s/ nocase ascii wide
                        $string54 = /demo\-controller\.exe\s/ nocase ascii wide
                        $string55 = /exe_stager\.exe/ nocase ascii wide
                        $string56 = /ExeStager\.csproj/ nocase ascii wide
                        $string57 = /ExternalC2\.Net/ nocase ascii wide
                        $string58 = /ExternalC2\.Net\./ nocase ascii wide
                        $string59 = /ExternalC2\\/ nocase ascii wide
                        $string60 = "GenerateReverseTcpDrone" nocase ascii wide
                        $string61 = /http.{0,100}127\.0\.0\.1\:50050/ nocase ascii wide
                        $string62 = /http.{0,100}localhost\:50050/ nocase ascii wide
                        $string63 = /IPeerToPeerService\./ nocase ascii wide
                        $string64 = /IReversePortForwardService\./ nocase ascii wide
                        $string65 = /PayloadFormat\.ASSEMBLY/ nocase ascii wide
                        $string66 = /PayloadFormat\.DLL/ nocase ascii wide
                        $string67 = /PayloadFormat\.EXE/ nocase ascii wide
                        $string68 = /PayloadFormat\.POWERSHELL/ nocase ascii wide
                        $string69 = /PayloadFormat\.SHELLCODE/ nocase ascii wide
                        $string70 = /PayloadFormat\.SVC_EXE/ nocase ascii wide
                        $string71 = /PayloadService\./ nocase ascii wide
                        $string72 = /PayloadType\.BIND_PIPE/ nocase ascii wide
                        $string73 = /PayloadType\.EXTERNAL/ nocase ascii wide
                        $string74 = /PayloadType\.HTTP/ nocase ascii wide
                        $string75 = /PayloadType\.REVERSE_TCP/ nocase ascii wide
                        $string76 = /PELoader\/PeLoader\./ nocase ascii wide
                        $string77 = "rasta-mouse/SharpC2" nocase ascii wide
                        $string78 = /Resources\/drone\.dll/ nocase ascii wide
                        $string79 = "SharpC2 " nocase ascii wide
                        $string80 = /SharpC2.{0,100}\.cs/ nocase ascii wide
                        $string81 = /SharpC2.{0,100}\.exe/ nocase ascii wide
                        $string82 = /sharpc2.{0,100}client\-windows\.zip/ nocase ascii wide
                        $string83 = /SharpC2\./ nocase ascii wide
                        $string84 = /SharpC2\.API/ nocase ascii wide
                        $string85 = "SharpC2Event" nocase ascii wide
                        $string86 = "SharpC2Hub" nocase ascii wide
                        $string87 = "SharpC2Webhook" nocase ascii wide
                        $string88 = /Stagers\\ExeStager\\/ nocase ascii wide
                        $string89 = /Stagers\\SvcStager\\/ nocase ascii wide
                        $string90 = /svc_stager\.exe/ nocase ascii wide
                        $string91 = /TeamServer\.C2Profiles/ nocase ascii wide
                        $string92 = "TeamServer/Filters/InjectionFilters" nocase ascii wide
                        $string93 = /TeamServer\/Pivots\/.{0,100}\./ nocase ascii wide
                        $string94 = /TeamServer\\TeamServer\./ nocase ascii wide
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