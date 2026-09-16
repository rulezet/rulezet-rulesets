rule SlinkyCat
{
    meta:
        description = "Detection patterns for the tool 'SlinkyCat' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SlinkyCat"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/SlinkyCat\.git/ nocase ascii wide
                        $string2 = "DNet-EnumerateAllDomainUserAccounts" nocase ascii wide
                        $string3 = "DNet-ListAccountsByDescription" nocase ascii wide
                        $string4 = "DNet-ListDomainUserAccountsWithCompletedADDescription" nocase ascii wide
                        $string5 = "DNet-ListUsersInDomainAdminsGroup" nocase ascii wide
                        $string6 = "EnumerateAllDomainControllers" nocase ascii wide
                        $string7 = "FindAdminAccessComputers" nocase ascii wide
                        $string8 = "Invoke-SlinkyCat" nocase ascii wide
                        $string9 = "LaresLLC/SlinkyCat" nocase ascii wide
                        $string10 = "ListAccountsWithSPN" nocase ascii wide
                        $string11 = "ListDescriptionContainsPass" nocase ascii wide
                        $string12 = "ListDomainAdmins" nocase ascii wide
                        $string13 = "ListDomainGroupsLocalAdmin" nocase ascii wide
                        $string14 = "ListNeverLoggedInAccounts" nocase ascii wide
                        $string15 = "ListPasswordNeverExpire" nocase ascii wide
                        $string16 = "ListUsersLastPasswordChange" nocase ascii wide
                        $string17 = "ListUsersNoPasswordRequired" nocase ascii wide
                        $string18 = "ListUsersPasswordMustChange" nocase ascii wide
                        $string19 = "ListUsersPasswordNotChanged" nocase ascii wide
                        $string20 = /output\/AccountsWithSPN\.txt/ nocase ascii wide
                        $string21 = /output\/AdminAccessComputers\.txt/ nocase ascii wide
                        $string22 = /output\/AllDomainControllers\.txt/ nocase ascii wide
                        $string23 = /output\/AllDomainGroups\.txt/ nocase ascii wide
                        $string24 = /output\/AllDomainHosts\.txt/ nocase ascii wide
                        $string25 = /output\/AllDomainUserAccounts\.txt/ nocase ascii wide
                        $string26 = /output\/AllDomainUsers\.txt/ nocase ascii wide
                        $string27 = /output\/AllServers\.txt/ nocase ascii wide
                        $string28 = /output\/AllServers2k12\.txt/ nocase ascii wide
                        $string29 = /output\/AllServers2k16\.txt/ nocase ascii wide
                        $string30 = /output\/AllServers2k19\.txt/ nocase ascii wide
                        $string31 = /output\/AllServers2k22\.txt/ nocase ascii wide
                        $string32 = /output\/AllServers2k8\.txt/ nocase ascii wide
                        $string33 = /output\/AllTrusts\.txt/ nocase ascii wide
                        $string34 = /output\/CompletedDescriptionField\.txt/ nocase ascii wide
                        $string35 = /output\/DescriptionContainsPass\.txt/ nocase ascii wide
                        $string36 = /output\/DNETAccountsByDescription\.txt/ nocase ascii wide
                        $string37 = /output\/DomainAdmins\.txt/ nocase ascii wide
                        $string38 = /output\/DomainGroupsLocalAdmin\.txt/ nocase ascii wide
                        $string39 = /output\/DomainUserAccountsWithCompletedADDescription\.txt/ nocase ascii wide
                        $string40 = /output\/ExchangeServers\.txt/ nocase ascii wide
                        $string41 = /output\/NeverLoggedInAccounts\.txt/ nocase ascii wide
                        $string42 = /output\/NonDCWindows10Computers\.txt/ nocase ascii wide
                        $string43 = /output\/NonDCWindows11Computers\.txt/ nocase ascii wide
                        $string44 = /output\/NonDCWindows7Computers\.txt/ nocase ascii wide
                        $string45 = /output\/PasswordNeverExpire\.txt/ nocase ascii wide
                        $string46 = /output\/RDPMachines\.txt/ nocase ascii wide
                        $string47 = /output\/UsersInDomainAdminsGroup\.txt/ nocase ascii wide
                        $string48 = /output\/UsersLastPasswordChange\.txt/ nocase ascii wide
                        $string49 = /output\/UsersNoPasswordRequired\.txt/ nocase ascii wide
                        $string50 = /output\/UsersPasswordMustChange\.txt/ nocase ascii wide
                        $string51 = /output\/UsersPasswordNotChanged\.txt/ nocase ascii wide
                        $string52 = /output\/WinRMMachines\.txt/ nocase ascii wide
                        $string53 = /SlinkyCat\.ps1/ nocase ascii wide
                        $string54 = "SlinkyCat-main" nocase ascii wide
                        $string55 = /System\.DirectoryServices\.AccountManagement\.GroupPrincipal.{0,1000}FindByIdentity.{0,1000}D/ nocase ascii wide
                        $string56 = "TestWinRMMachines" nocase ascii wide

    condition:
        any of them
}