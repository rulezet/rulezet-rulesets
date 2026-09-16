rule seatbelt
{
    meta:
        description = "Detection patterns for the tool 'seatbelt' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "seatbelt"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " --Args AntiVirus --XorKey" nocase ascii wide
                        $string2 = " --args whoami" nocase ascii wide
                        $string3 = /\.exe\s\s\-group\=remote\s\-computername\=/ nocase ascii wide
                        $string4 = /\.exe\s\-group\=all\s/ nocase ascii wide
                        $string5 = /\.exe\s\-group\=all\s\-AuditPolicies/ nocase ascii wide
                        $string6 = /\.exe\s\-group\=all\s\-full/ nocase ascii wide
                        $string7 = /\.exe\s\-group\=remote\s/ nocase ascii wide
                        $string8 = /\.exe\s\-group\=system\s/ nocase ascii wide
                        $string9 = /\.exe\s\-group\=user\s/ nocase ascii wide
                        $string10 = /\.exe\sNonstandardProcesses/ nocase ascii wide
                        $string11 = /\.exe\sNTLMSettings/ nocase ascii wide
                        $string12 = /\.exe\s\-q\sInterestingProcesses/ nocase ascii wide
                        $string13 = /\.exe\s\-q\sPowerShell/ nocase ascii wide
                        $string14 = /\.exe\s\-q\sWindowsDefender/ nocase ascii wide
                        $string15 = /\/Seatbelt\.exe/ nocase ascii wide
                        $string16 = /\/Seatbelt\.git/ nocase ascii wide
                        $string17 = "/Seatbelt/Commands" nocase ascii wide
                        $string18 = /\\Seatbelt\.exe/ nocase ascii wide
                        $string19 = /\\Seatbelt\.sln/ nocase ascii wide
                        $string20 = /\\Seatbelt\\Commands\\/ nocase ascii wide
                        $string21 = /\\Seatbelt\\Program\.cs/ nocase ascii wide
                        $string22 = /\\Seatbelt\\Seatbelt\.cs/ nocase ascii wide
                        $string23 = ">Seatbelt<" nocase ascii wide
                        $string24 = "0dece401c686c54a06aba232c7bf4f80b49e4087aed13078c4721676341db992" nocase ascii wide
                        $string25 = "0fa3195520e1b55fa7d36818a916b9b8cee1ee673997ec71c18a52947697d2fb" nocase ascii wide
                        $string26 = "26edf5820094951dd18e20e86b1151d7113f1e17b64f1d3817d4995885559850" nocase ascii wide
                        $string27 = /ACE_Get\-KerberosTicketCache\.ps1/ nocase ascii wide
                        $string28 = "AEC32155-D589-4150-8FE7-2900DF4554C8" nocase ascii wide
                        $string29 = "--assemblyargs AntiVirus AppLocker" nocase ascii wide
                        $string30 = "b31fc5e7f730a95d7cfc83476e543e00f94bae8f3635101c4b991f0d664ac0d2" nocase ascii wide
                        $string31 = "GhostPack/Seatbelt" nocase ascii wide
                        $string32 = /Invoke\-WCMDump\.ps1/ nocase ascii wide
                        $string33 = /Seatbelt.{0,100}\s\-group\=all/ nocase ascii wide
                        $string34 = /Seatbelt\.Commands\.Windows/ nocase ascii wide
                        $string35 = /Seatbelt\.exe/ nocase ascii wide
                        $string36 = /SeatbeltNet.{0,100}\.exe/ nocase ascii wide
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