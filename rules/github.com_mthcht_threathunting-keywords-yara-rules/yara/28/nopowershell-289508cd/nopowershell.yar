rule nopowershell
{
    meta:
        description = "Detection patterns for the tool 'nopowershell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nopowershell"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/nopowershell\.git/ nocase ascii wide
                        $string2 = "/NoPowerShell/" nocase ascii wide
                        $string3 = /\\CompressArchiveCommand\.cs/ nocase ascii wide
                        $string4 = /\\CopyItemCommand\.cs/ nocase ascii wide
                        $string5 = /\\DllExport\.bat/ nocase ascii wide
                        $string6 = /\\ExpandArchiveCommand\.cs/ nocase ascii wide
                        $string7 = /\\ExportCsvCommand\.cs/ nocase ascii wide
                        $string8 = /\\FormatListCommand\.cs/ nocase ascii wide
                        $string9 = /\\FormatTableCommand\.cs/ nocase ascii wide
                        $string10 = /\\GetADGroupCommand\.cs/ nocase ascii wide
                        $string11 = /\\GetADGroupMemberCommand\.cs/ nocase ascii wide
                        $string12 = /\\GetADObjectCommand\.cs/ nocase ascii wide
                        $string13 = /\\GetADTrustCommand\.cs/ nocase ascii wide
                        $string14 = /\\GetADUserCommand\.cs/ nocase ascii wide
                        $string15 = /\\GetChildItemCommand\.cs/ nocase ascii wide
                        $string16 = /\\GetClipboardCommand\.cs/ nocase ascii wide
                        $string17 = /\\GetCommandCommand\.cs/ nocase ascii wide
                        $string18 = /\\GetComputerInfoCommand\.cs/ nocase ascii wide
                        $string19 = /\\GetContentCommand\.cs/ nocase ascii wide
                        $string20 = /\\GetDnsClientCacheCommand\.cs/ nocase ascii wide
                        $string21 = /\\GetHelpCommand\.cs/ nocase ascii wide
                        $string22 = /\\GetHotFixCommand\.cs/ nocase ascii wide
                        $string23 = /\\GetItemPropertyCommand\.cs/ nocase ascii wide
                        $string24 = /\\GetItemPropertyValueCommand\.cs/ nocase ascii wide
                        $string25 = /\\GetLocalGroupCommand\.cs/ nocase ascii wide
                        $string26 = /\\GetLocalGroupMemberCommand\.cs/ nocase ascii wide
                        $string27 = /\\GetLocalUserCommand\.cs/ nocase ascii wide
                        $string28 = /\\GetNetIPAddressCommand\.cs/ nocase ascii wide
                        $string29 = /\\GetNetNeighborCommand\.cs/ nocase ascii wide
                        $string30 = /\\GetNetRouteCommand\.cs/ nocase ascii wide
                        $string31 = /\\GetNetTCPConnectionCommand\.cs/ nocase ascii wide
                        $string32 = /\\GetProcessCommand\.cs/ nocase ascii wide
                        $string33 = /\\GetPSDriveCommand\.cs/ nocase ascii wide
                        $string34 = /\\GetRemoteSmbShareCommand\.cs/ nocase ascii wide
                        $string35 = /\\GetSmbMappingCommand\.cs/ nocase ascii wide
                        $string36 = /\\GetSmbShareCommand\.cs/ nocase ascii wide
                        $string37 = /\\GetWhoamiCommand\.cs/ nocase ascii wide
                        $string38 = /\\GetWinStationCommand\.cs/ nocase ascii wide
                        $string39 = /\\GetWmiObjectCommand\.cs/ nocase ascii wide
                        $string40 = /\\InvokeWebRequestCommand\.cs/ nocase ascii wide
                        $string41 = /\\InvokeWmiMethodCommand\.cs/ nocase ascii wide
                        $string42 = /\\MeasureObjectCommand\.cs/ nocase ascii wide
                        $string43 = /\\NoPowerShell/ nocase ascii wide
                        $string44 = /\\OutFileCommand\.cs/ nocase ascii wide
                        $string45 = /\\RemoveItemCommand\.cs/ nocase ascii wide
                        $string46 = /\\ResolveDnsNameCommand\.cs/ nocase ascii wide
                        $string47 = /\\SelectObjectCommand\.cs/ nocase ascii wide
                        $string48 = /\\SetClipboardCommand\.cs/ nocase ascii wide
                        $string49 = /\\SortObjectCommand\.cs/ nocase ascii wide
                        $string50 = /\\StopProcessCommand\.cs/ nocase ascii wide
                        $string51 = /\\TestNetConnectionCommand\.cs/ nocase ascii wide
                        $string52 = /\\Tmp\\nc\.exe/ nocase ascii wide
                        $string53 = /\\Tmp\\netcat\.exe/ nocase ascii wide
                        $string54 = /\\WhereObjectCommand\.cs/ nocase ascii wide
                        $string55 = /\\Windows\\System32\\nc\.exe/ nocase ascii wide
                        $string56 = /\\WriteOutputCommand\.cs/ nocase ascii wide
                        $string57 = /\=\=\sNoPowerShell\sv.{0,1000}\s\=\=/ nocase ascii wide
                        $string58 = /\=\=\sNoPowerShell\sv.{0,1000}\s\=\=/ nocase ascii wide
                        $string59 = "555AD0AC-1FDB-4016-8257-170A74CB2F55" nocase ascii wide
                        $string60 = "555AD0AC-1FDB-4016-8257-170A74CB2F55" nocase ascii wide
                        $string61 = "bitsadmin/nopowershell" nocase ascii wide
                        $string62 = /BOFNET\.Bofs\.Jobs/ nocase ascii wide
                        $string63 = /bofnet\.cna/ nocase ascii wide
                        $string64 = /BOFNET\.dll/ nocase ascii wide
                        $string65 = "bofnet_execute " nocase ascii wide
                        $string66 = /bofnet_execute\.cpp/ nocase ascii wide
                        $string67 = /bofnet_execute\.cpp\.x64\.obj/ nocase ascii wide
                        $string68 = /bofnet_execute\.cpp\.x64\.obj/ nocase ascii wide
                        $string69 = /bofnet_execute\.cpp\.x86\.obj/ nocase ascii wide
                        $string70 = /bofnet_execute\.cpp\.x86\.obj/ nocase ascii wide
                        $string71 = "bofnet_load " nocase ascii wide
                        $string72 = /GetWhoamiCommand\.cs/ nocase ascii wide
                        $string73 = /https\:\/\/github\.com\/bitsadmin\// nocase ascii wide
                        $string74 = /NoPowerShell\.cna/ nocase ascii wide
                        $string75 = /NoPowerShell\.Commands/ nocase ascii wide
                        $string76 = /NoPowerShell\.Commands\.Management/ nocase ascii wide
                        $string77 = /NoPowerShell\.csproj/ nocase ascii wide
                        $string78 = /NoPowerShell\.dll/ nocase ascii wide
                        $string79 = /NoPowerShell\.exe/ nocase ascii wide
                        $string80 = /NoPowerShell\.sln/ nocase ascii wide
                        $string81 = /NoPowerShell_trunk\.zip/ nocase ascii wide
                        $string82 = /NoPowerShell32\.dll/ nocase ascii wide
                        $string83 = /NoPowerShell64\.dll/ nocase ascii wide
                        $string84 = /NoPowerShellDll\./ nocase ascii wide
                        $string85 = "nps whoami" nocase ascii wide
                        $string86 = "PublicKeyToken=8337224c9ad9e356" nocase ascii wide

    condition:
        any of them
}