rule rule_SharpUp_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharpUp' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpUp"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SharpUp_offensive_tool_keyword = " audit AlwaysInstallElevated" nocase ascii wide
                        $string2_SharpUp_offensive_tool_keyword = " audit CachedGPPPassword" nocase ascii wide
                        $string3_SharpUp_offensive_tool_keyword = " audit DomainGPPPassword" nocase ascii wide
                        $string4_SharpUp_offensive_tool_keyword = " audit HijackablePaths" nocase ascii wide
                        $string5_SharpUp_offensive_tool_keyword = " audit McAfeeSitelistFiles" nocase ascii wide
                        $string6_SharpUp_offensive_tool_keyword = " audit ModifiableScheduledTask" nocase ascii wide
                        $string7_SharpUp_offensive_tool_keyword = " audit ModifiableServiceBinaries" nocase ascii wide
                        $string8_SharpUp_offensive_tool_keyword = " audit ModifiableServiceRegistryKeys" nocase ascii wide
                        $string9_SharpUp_offensive_tool_keyword = " audit ModifiableServices" nocase ascii wide
                        $string10_SharpUp_offensive_tool_keyword = " audit ProcessDLLHijack" nocase ascii wide
                        $string11_SharpUp_offensive_tool_keyword = " audit RegistryAutoLogons" nocase ascii wide
                        $string12_SharpUp_offensive_tool_keyword = " audit RegistryAutoruns" nocase ascii wide
                        $string13_SharpUp_offensive_tool_keyword = " audit TokenPrivileges" nocase ascii wide
                        $string14_SharpUp_offensive_tool_keyword = " audit UnattendedInstallFiles" nocase ascii wide
                        $string15_SharpUp_offensive_tool_keyword = " audit UnquotedServicePath" nocase ascii wide
                        $string16_SharpUp_offensive_tool_keyword = /\.exe\sAlwaysInstallElevated/ nocase ascii wide
                        $string17_SharpUp_offensive_tool_keyword = /\.exe\saudit\sHijackablePaths/ nocase ascii wide
                        $string18_SharpUp_offensive_tool_keyword = /\.exe\saudit\sModifiableServices/ nocase ascii wide
                        $string19_SharpUp_offensive_tool_keyword = /\.exe\sCachedGPPPassword/ nocase ascii wide
                        $string20_SharpUp_offensive_tool_keyword = /\.exe\sDomainGPPPassword/ nocase ascii wide
                        $string21_SharpUp_offensive_tool_keyword = /\.exe\sHijackablePaths/ nocase ascii wide
                        $string22_SharpUp_offensive_tool_keyword = /\.exe\sMcAfeeSitelistFiles/ nocase ascii wide
                        $string23_SharpUp_offensive_tool_keyword = /\.exe\sModifiableScheduledTask/ nocase ascii wide
                        $string24_SharpUp_offensive_tool_keyword = /\.exe\sModifiableServiceBinaries/ nocase ascii wide
                        $string25_SharpUp_offensive_tool_keyword = /\.exe\sModifiableServiceRegistryKeys/ nocase ascii wide
                        $string26_SharpUp_offensive_tool_keyword = /\.exe\sModifiableServices/ nocase ascii wide
                        $string27_SharpUp_offensive_tool_keyword = /\.exe\sProcessDLLHijack/ nocase ascii wide
                        $string28_SharpUp_offensive_tool_keyword = /\.exe\sRegistryAutoLogons/ nocase ascii wide
                        $string29_SharpUp_offensive_tool_keyword = /\.exe\sRegistryAutoruns/ nocase ascii wide
                        $string30_SharpUp_offensive_tool_keyword = /\.exe\sTokenPrivileges/ nocase ascii wide
                        $string31_SharpUp_offensive_tool_keyword = /\.exe\sUnattendedInstallFiles/ nocase ascii wide
                        $string32_SharpUp_offensive_tool_keyword = /\.exe\sUnquotedServicePath/ nocase ascii wide
                        $string33_SharpUp_offensive_tool_keyword = /\/SharpUp\.exe/ nocase ascii wide
                        $string34_SharpUp_offensive_tool_keyword = /\/SharpUp\.git/ nocase ascii wide
                        $string35_SharpUp_offensive_tool_keyword = /\[\!\]\sModifialbe\sscheduled\stasks\swere\snot\sevaluated\sdue\sto\spermissions/ nocase ascii wide
                        $string36_SharpUp_offensive_tool_keyword = /\[\+\]\sHijackable\sDLL\:\s/ nocase ascii wide
                        $string37_SharpUp_offensive_tool_keyword = /\[\+\]\sPotenatially\sHijackable\sDLL\:\s/ nocase ascii wide
                        $string38_SharpUp_offensive_tool_keyword = /\\AlwaysInstallElevated\.cs/ nocase ascii wide
                        $string39_SharpUp_offensive_tool_keyword = /\\CachedGPPPassword\.cs/ nocase ascii wide
                        $string40_SharpUp_offensive_tool_keyword = /\\DomainGPPPassword\.cs/ nocase ascii wide
                        $string41_SharpUp_offensive_tool_keyword = /\\HijackablePaths\.cs/ nocase ascii wide
                        $string42_SharpUp_offensive_tool_keyword = /\\ProcessDLLHijack\.cs/ nocase ascii wide
                        $string43_SharpUp_offensive_tool_keyword = /\\SharpUp\.csproj/ nocase ascii wide
                        $string44_SharpUp_offensive_tool_keyword = /\\SharpUp\.exe/ nocase ascii wide
                        $string45_SharpUp_offensive_tool_keyword = /\\SharpUp\.pdb/ nocase ascii wide
                        $string46_SharpUp_offensive_tool_keyword = /\\SharpUp\.sln/ nocase ascii wide
                        $string47_SharpUp_offensive_tool_keyword = /\\SharpUp\\/ nocase ascii wide
                        $string48_SharpUp_offensive_tool_keyword = /\\SharpUp\-master/ nocase ascii wide
                        $string49_SharpUp_offensive_tool_keyword = /\\UnquotedServicePath\.cs/ nocase ascii wide
                        $string50_SharpUp_offensive_tool_keyword = /\]\sAlready\sin\shigh\sintegrity\,\sno\sneed\sto\sprivesc\!/ nocase ascii wide
                        $string51_SharpUp_offensive_tool_keyword = /\]\sCompleted\sPrivesc\sChecks\sin\s/ nocase ascii wide
                        $string52_SharpUp_offensive_tool_keyword = /\]\sIn\smedium\sintegrity\sbut\suser\sis\sa\slocal\sadministrator\-\sUAC\scan\sbe\sbypassed\./ nocase ascii wide
                        $string53_SharpUp_offensive_tool_keyword = "=== SharpUp: Running Privilege Escalation Checks ===" nocase ascii wide
                        $string54_SharpUp_offensive_tool_keyword = ">SharpUp<" nocase ascii wide
                        $string55_SharpUp_offensive_tool_keyword = "Already in high integrity, no need to privesc!" nocase ascii wide
                        $string56_SharpUp_offensive_tool_keyword = "FDD654F5-5C54-4D93-BF8E-FAF11B00E3E9" nocase ascii wide
                        $string57_SharpUp_offensive_tool_keyword = "GhostPack/SharpUp" nocase ascii wide
                        $string58_SharpUp_offensive_tool_keyword = "In medium integrity but user is a local administrator- UAC can be bypassed" nocase ascii wide
                        $string59_SharpUp_offensive_tool_keyword = "ParseGPPPasswordFromXml" nocase ascii wide
                        $string60_SharpUp_offensive_tool_keyword = /SharpUp\.exe/ nocase ascii wide
                        $string61_SharpUp_offensive_tool_keyword = /using\sSharpUp\.Classes/ nocase ascii wide
                        $string62_SharpUp_offensive_tool_keyword = /using\sstatic\sSharpUp\.Utilities/ nocase ascii wide

    condition:
        any of them
}