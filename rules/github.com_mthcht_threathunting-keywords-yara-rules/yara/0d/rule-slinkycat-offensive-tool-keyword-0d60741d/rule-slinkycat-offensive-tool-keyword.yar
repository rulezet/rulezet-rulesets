rule rule_SlinkyCat_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SlinkyCat' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SlinkyCat"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SlinkyCat_offensive_tool_keyword = /\/SlinkyCat\.git/ nocase ascii wide
                        $string2_SlinkyCat_offensive_tool_keyword = "DNet-EnumerateAllDomainUserAccounts" nocase ascii wide
                        $string3_SlinkyCat_offensive_tool_keyword = "DNet-ListAccountsByDescription" nocase ascii wide
                        $string4_SlinkyCat_offensive_tool_keyword = "DNet-ListDomainUserAccountsWithCompletedADDescription" nocase ascii wide
                        $string5_SlinkyCat_offensive_tool_keyword = "DNet-ListUsersInDomainAdminsGroup" nocase ascii wide
                        $string6_SlinkyCat_offensive_tool_keyword = "EnumerateAllDomainControllers" nocase ascii wide
                        $string7_SlinkyCat_offensive_tool_keyword = "FindAdminAccessComputers" nocase ascii wide
                        $string8_SlinkyCat_offensive_tool_keyword = "Invoke-SlinkyCat" nocase ascii wide
                        $string9_SlinkyCat_offensive_tool_keyword = "LaresLLC/SlinkyCat" nocase ascii wide
                        $string10_SlinkyCat_offensive_tool_keyword = "ListAccountsWithSPN" nocase ascii wide
                        $string11_SlinkyCat_offensive_tool_keyword = "ListDescriptionContainsPass" nocase ascii wide
                        $string12_SlinkyCat_offensive_tool_keyword = "ListDomainAdmins" nocase ascii wide
                        $string13_SlinkyCat_offensive_tool_keyword = "ListDomainGroupsLocalAdmin" nocase ascii wide
                        $string14_SlinkyCat_offensive_tool_keyword = "ListNeverLoggedInAccounts" nocase ascii wide
                        $string15_SlinkyCat_offensive_tool_keyword = "ListPasswordNeverExpire" nocase ascii wide
                        $string16_SlinkyCat_offensive_tool_keyword = "ListUsersLastPasswordChange" nocase ascii wide
                        $string17_SlinkyCat_offensive_tool_keyword = "ListUsersNoPasswordRequired" nocase ascii wide
                        $string18_SlinkyCat_offensive_tool_keyword = "ListUsersPasswordMustChange" nocase ascii wide
                        $string19_SlinkyCat_offensive_tool_keyword = "ListUsersPasswordNotChanged" nocase ascii wide
                        $string20_SlinkyCat_offensive_tool_keyword = /output\/AccountsWithSPN\.txt/ nocase ascii wide
                        $string21_SlinkyCat_offensive_tool_keyword = /output\/AdminAccessComputers\.txt/ nocase ascii wide
                        $string22_SlinkyCat_offensive_tool_keyword = /output\/AllDomainControllers\.txt/ nocase ascii wide
                        $string23_SlinkyCat_offensive_tool_keyword = /output\/AllDomainGroups\.txt/ nocase ascii wide
                        $string24_SlinkyCat_offensive_tool_keyword = /output\/AllDomainHosts\.txt/ nocase ascii wide
                        $string25_SlinkyCat_offensive_tool_keyword = /output\/AllDomainUserAccounts\.txt/ nocase ascii wide
                        $string26_SlinkyCat_offensive_tool_keyword = /output\/AllDomainUsers\.txt/ nocase ascii wide
                        $string27_SlinkyCat_offensive_tool_keyword = /output\/AllServers\.txt/ nocase ascii wide
                        $string28_SlinkyCat_offensive_tool_keyword = /output\/AllServers2k12\.txt/ nocase ascii wide
                        $string29_SlinkyCat_offensive_tool_keyword = /output\/AllServers2k16\.txt/ nocase ascii wide
                        $string30_SlinkyCat_offensive_tool_keyword = /output\/AllServers2k19\.txt/ nocase ascii wide
                        $string31_SlinkyCat_offensive_tool_keyword = /output\/AllServers2k22\.txt/ nocase ascii wide
                        $string32_SlinkyCat_offensive_tool_keyword = /output\/AllServers2k8\.txt/ nocase ascii wide
                        $string33_SlinkyCat_offensive_tool_keyword = /output\/AllTrusts\.txt/ nocase ascii wide
                        $string34_SlinkyCat_offensive_tool_keyword = /output\/CompletedDescriptionField\.txt/ nocase ascii wide
                        $string35_SlinkyCat_offensive_tool_keyword = /output\/DescriptionContainsPass\.txt/ nocase ascii wide
                        $string36_SlinkyCat_offensive_tool_keyword = /output\/DNETAccountsByDescription\.txt/ nocase ascii wide
                        $string37_SlinkyCat_offensive_tool_keyword = /output\/DomainAdmins\.txt/ nocase ascii wide
                        $string38_SlinkyCat_offensive_tool_keyword = /output\/DomainGroupsLocalAdmin\.txt/ nocase ascii wide
                        $string39_SlinkyCat_offensive_tool_keyword = /output\/DomainUserAccountsWithCompletedADDescription\.txt/ nocase ascii wide
                        $string40_SlinkyCat_offensive_tool_keyword = /output\/ExchangeServers\.txt/ nocase ascii wide
                        $string41_SlinkyCat_offensive_tool_keyword = /output\/NeverLoggedInAccounts\.txt/ nocase ascii wide
                        $string42_SlinkyCat_offensive_tool_keyword = /output\/NonDCWindows10Computers\.txt/ nocase ascii wide
                        $string43_SlinkyCat_offensive_tool_keyword = /output\/NonDCWindows11Computers\.txt/ nocase ascii wide
                        $string44_SlinkyCat_offensive_tool_keyword = /output\/NonDCWindows7Computers\.txt/ nocase ascii wide
                        $string45_SlinkyCat_offensive_tool_keyword = /output\/PasswordNeverExpire\.txt/ nocase ascii wide
                        $string46_SlinkyCat_offensive_tool_keyword = /output\/RDPMachines\.txt/ nocase ascii wide
                        $string47_SlinkyCat_offensive_tool_keyword = /output\/UsersInDomainAdminsGroup\.txt/ nocase ascii wide
                        $string48_SlinkyCat_offensive_tool_keyword = /output\/UsersLastPasswordChange\.txt/ nocase ascii wide
                        $string49_SlinkyCat_offensive_tool_keyword = /output\/UsersNoPasswordRequired\.txt/ nocase ascii wide
                        $string50_SlinkyCat_offensive_tool_keyword = /output\/UsersPasswordMustChange\.txt/ nocase ascii wide
                        $string51_SlinkyCat_offensive_tool_keyword = /output\/UsersPasswordNotChanged\.txt/ nocase ascii wide
                        $string52_SlinkyCat_offensive_tool_keyword = /output\/WinRMMachines\.txt/ nocase ascii wide
                        $string53_SlinkyCat_offensive_tool_keyword = /SlinkyCat\.ps1/ nocase ascii wide
                        $string54_SlinkyCat_offensive_tool_keyword = "SlinkyCat-main" nocase ascii wide
                        $string55_SlinkyCat_offensive_tool_keyword = /System\.DirectoryServices\.AccountManagement\.GroupPrincipal.{0,100}FindByIdentity.{0,100}D/ nocase ascii wide
                        $string56_SlinkyCat_offensive_tool_keyword = "TestWinRMMachines" nocase ascii wide
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