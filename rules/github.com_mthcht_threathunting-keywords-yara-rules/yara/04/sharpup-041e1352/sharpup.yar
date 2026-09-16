rule SharpUp
{
    meta:
        description = "Detection patterns for the tool 'SharpUp' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpUp"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " audit AlwaysInstallElevated" nocase ascii wide
                        $string2 = " audit CachedGPPPassword" nocase ascii wide
                        $string3 = " audit DomainGPPPassword" nocase ascii wide
                        $string4 = " audit HijackablePaths" nocase ascii wide
                        $string5 = " audit McAfeeSitelistFiles" nocase ascii wide
                        $string6 = " audit ModifiableScheduledTask" nocase ascii wide
                        $string7 = " audit ModifiableServiceBinaries" nocase ascii wide
                        $string8 = " audit ModifiableServiceRegistryKeys" nocase ascii wide
                        $string9 = " audit ModifiableServices" nocase ascii wide
                        $string10 = " audit ProcessDLLHijack" nocase ascii wide
                        $string11 = " audit RegistryAutoLogons" nocase ascii wide
                        $string12 = " audit RegistryAutoruns" nocase ascii wide
                        $string13 = " audit TokenPrivileges" nocase ascii wide
                        $string14 = " audit UnattendedInstallFiles" nocase ascii wide
                        $string15 = " audit UnquotedServicePath" nocase ascii wide
                        $string16 = /\.exe\sAlwaysInstallElevated/ nocase ascii wide
                        $string17 = /\.exe\saudit\sHijackablePaths/ nocase ascii wide
                        $string18 = /\.exe\saudit\sModifiableServices/ nocase ascii wide
                        $string19 = /\.exe\sCachedGPPPassword/ nocase ascii wide
                        $string20 = /\.exe\sDomainGPPPassword/ nocase ascii wide
                        $string21 = /\.exe\sHijackablePaths/ nocase ascii wide
                        $string22 = /\.exe\sMcAfeeSitelistFiles/ nocase ascii wide
                        $string23 = /\.exe\sModifiableScheduledTask/ nocase ascii wide
                        $string24 = /\.exe\sModifiableServiceBinaries/ nocase ascii wide
                        $string25 = /\.exe\sModifiableServiceRegistryKeys/ nocase ascii wide
                        $string26 = /\.exe\sModifiableServices/ nocase ascii wide
                        $string27 = /\.exe\sProcessDLLHijack/ nocase ascii wide
                        $string28 = /\.exe\sRegistryAutoLogons/ nocase ascii wide
                        $string29 = /\.exe\sRegistryAutoruns/ nocase ascii wide
                        $string30 = /\.exe\sTokenPrivileges/ nocase ascii wide
                        $string31 = /\.exe\sUnattendedInstallFiles/ nocase ascii wide
                        $string32 = /\.exe\sUnquotedServicePath/ nocase ascii wide
                        $string33 = /\/SharpUp\.exe/ nocase ascii wide
                        $string34 = /\/SharpUp\.git/ nocase ascii wide
                        $string35 = /\[\!\]\sModifialbe\sscheduled\stasks\swere\snot\sevaluated\sdue\sto\spermissions/ nocase ascii wide
                        $string36 = /\[\+\]\sHijackable\sDLL\:\s/ nocase ascii wide
                        $string37 = /\[\+\]\sPotenatially\sHijackable\sDLL\:\s/ nocase ascii wide
                        $string38 = /\\AlwaysInstallElevated\.cs/ nocase ascii wide
                        $string39 = /\\CachedGPPPassword\.cs/ nocase ascii wide
                        $string40 = /\\DomainGPPPassword\.cs/ nocase ascii wide
                        $string41 = /\\HijackablePaths\.cs/ nocase ascii wide
                        $string42 = /\\ProcessDLLHijack\.cs/ nocase ascii wide
                        $string43 = /\\SharpUp\.csproj/ nocase ascii wide
                        $string44 = /\\SharpUp\.exe/ nocase ascii wide
                        $string45 = /\\SharpUp\.pdb/ nocase ascii wide
                        $string46 = /\\SharpUp\.sln/ nocase ascii wide
                        $string47 = /\\SharpUp\\/ nocase ascii wide
                        $string48 = /\\SharpUp\-master/ nocase ascii wide
                        $string49 = /\\UnquotedServicePath\.cs/ nocase ascii wide
                        $string50 = /\]\sAlready\sin\shigh\sintegrity\,\sno\sneed\sto\sprivesc\!/ nocase ascii wide
                        $string51 = /\]\sCompleted\sPrivesc\sChecks\sin\s/ nocase ascii wide
                        $string52 = /\]\sIn\smedium\sintegrity\sbut\suser\sis\sa\slocal\sadministrator\-\sUAC\scan\sbe\sbypassed\./ nocase ascii wide
                        $string53 = "=== SharpUp: Running Privilege Escalation Checks ===" nocase ascii wide
                        $string54 = ">SharpUp<" nocase ascii wide
                        $string55 = "Already in high integrity, no need to privesc!" nocase ascii wide
                        $string56 = "FDD654F5-5C54-4D93-BF8E-FAF11B00E3E9" nocase ascii wide
                        $string57 = "GhostPack/SharpUp" nocase ascii wide
                        $string58 = "In medium integrity but user is a local administrator- UAC can be bypassed" nocase ascii wide
                        $string59 = "ParseGPPPasswordFromXml" nocase ascii wide
                        $string60 = /SharpUp\.exe/ nocase ascii wide
                        $string61 = /using\sSharpUp\.Classes/ nocase ascii wide
                        $string62 = /using\sstatic\sSharpUp\.Utilities/ nocase ascii wide
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