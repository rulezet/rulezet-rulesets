rule rule_nopowershell_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'nopowershell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nopowershell"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_nopowershell_offensive_tool_keyword = /\/nopowershell\.git/ nocase ascii wide
                        $string2_nopowershell_offensive_tool_keyword = "/NoPowerShell/" nocase ascii wide
                        $string3_nopowershell_offensive_tool_keyword = /\\CompressArchiveCommand\.cs/ nocase ascii wide
                        $string4_nopowershell_offensive_tool_keyword = /\\CopyItemCommand\.cs/ nocase ascii wide
                        $string5_nopowershell_offensive_tool_keyword = /\\DllExport\.bat/ nocase ascii wide
                        $string6_nopowershell_offensive_tool_keyword = /\\ExpandArchiveCommand\.cs/ nocase ascii wide
                        $string7_nopowershell_offensive_tool_keyword = /\\ExportCsvCommand\.cs/ nocase ascii wide
                        $string8_nopowershell_offensive_tool_keyword = /\\FormatListCommand\.cs/ nocase ascii wide
                        $string9_nopowershell_offensive_tool_keyword = /\\FormatTableCommand\.cs/ nocase ascii wide
                        $string10_nopowershell_offensive_tool_keyword = /\\GetADGroupCommand\.cs/ nocase ascii wide
                        $string11_nopowershell_offensive_tool_keyword = /\\GetADGroupMemberCommand\.cs/ nocase ascii wide
                        $string12_nopowershell_offensive_tool_keyword = /\\GetADObjectCommand\.cs/ nocase ascii wide
                        $string13_nopowershell_offensive_tool_keyword = /\\GetADTrustCommand\.cs/ nocase ascii wide
                        $string14_nopowershell_offensive_tool_keyword = /\\GetADUserCommand\.cs/ nocase ascii wide
                        $string15_nopowershell_offensive_tool_keyword = /\\GetChildItemCommand\.cs/ nocase ascii wide
                        $string16_nopowershell_offensive_tool_keyword = /\\GetClipboardCommand\.cs/ nocase ascii wide
                        $string17_nopowershell_offensive_tool_keyword = /\\GetCommandCommand\.cs/ nocase ascii wide
                        $string18_nopowershell_offensive_tool_keyword = /\\GetComputerInfoCommand\.cs/ nocase ascii wide
                        $string19_nopowershell_offensive_tool_keyword = /\\GetContentCommand\.cs/ nocase ascii wide
                        $string20_nopowershell_offensive_tool_keyword = /\\GetDnsClientCacheCommand\.cs/ nocase ascii wide
                        $string21_nopowershell_offensive_tool_keyword = /\\GetHelpCommand\.cs/ nocase ascii wide
                        $string22_nopowershell_offensive_tool_keyword = /\\GetHotFixCommand\.cs/ nocase ascii wide
                        $string23_nopowershell_offensive_tool_keyword = /\\GetItemPropertyCommand\.cs/ nocase ascii wide
                        $string24_nopowershell_offensive_tool_keyword = /\\GetItemPropertyValueCommand\.cs/ nocase ascii wide
                        $string25_nopowershell_offensive_tool_keyword = /\\GetLocalGroupCommand\.cs/ nocase ascii wide
                        $string26_nopowershell_offensive_tool_keyword = /\\GetLocalGroupMemberCommand\.cs/ nocase ascii wide
                        $string27_nopowershell_offensive_tool_keyword = /\\GetLocalUserCommand\.cs/ nocase ascii wide
                        $string28_nopowershell_offensive_tool_keyword = /\\GetNetIPAddressCommand\.cs/ nocase ascii wide
                        $string29_nopowershell_offensive_tool_keyword = /\\GetNetNeighborCommand\.cs/ nocase ascii wide
                        $string30_nopowershell_offensive_tool_keyword = /\\GetNetRouteCommand\.cs/ nocase ascii wide
                        $string31_nopowershell_offensive_tool_keyword = /\\GetNetTCPConnectionCommand\.cs/ nocase ascii wide
                        $string32_nopowershell_offensive_tool_keyword = /\\GetProcessCommand\.cs/ nocase ascii wide
                        $string33_nopowershell_offensive_tool_keyword = /\\GetPSDriveCommand\.cs/ nocase ascii wide
                        $string34_nopowershell_offensive_tool_keyword = /\\GetRemoteSmbShareCommand\.cs/ nocase ascii wide
                        $string35_nopowershell_offensive_tool_keyword = /\\GetSmbMappingCommand\.cs/ nocase ascii wide
                        $string36_nopowershell_offensive_tool_keyword = /\\GetSmbShareCommand\.cs/ nocase ascii wide
                        $string37_nopowershell_offensive_tool_keyword = /\\GetWhoamiCommand\.cs/ nocase ascii wide
                        $string38_nopowershell_offensive_tool_keyword = /\\GetWinStationCommand\.cs/ nocase ascii wide
                        $string39_nopowershell_offensive_tool_keyword = /\\GetWmiObjectCommand\.cs/ nocase ascii wide
                        $string40_nopowershell_offensive_tool_keyword = /\\InvokeWebRequestCommand\.cs/ nocase ascii wide
                        $string41_nopowershell_offensive_tool_keyword = /\\InvokeWmiMethodCommand\.cs/ nocase ascii wide
                        $string42_nopowershell_offensive_tool_keyword = /\\MeasureObjectCommand\.cs/ nocase ascii wide
                        $string43_nopowershell_offensive_tool_keyword = /\\NoPowerShell/ nocase ascii wide
                        $string44_nopowershell_offensive_tool_keyword = /\\OutFileCommand\.cs/ nocase ascii wide
                        $string45_nopowershell_offensive_tool_keyword = /\\RemoveItemCommand\.cs/ nocase ascii wide
                        $string46_nopowershell_offensive_tool_keyword = /\\ResolveDnsNameCommand\.cs/ nocase ascii wide
                        $string47_nopowershell_offensive_tool_keyword = /\\SelectObjectCommand\.cs/ nocase ascii wide
                        $string48_nopowershell_offensive_tool_keyword = /\\SetClipboardCommand\.cs/ nocase ascii wide
                        $string49_nopowershell_offensive_tool_keyword = /\\SortObjectCommand\.cs/ nocase ascii wide
                        $string50_nopowershell_offensive_tool_keyword = /\\StopProcessCommand\.cs/ nocase ascii wide
                        $string51_nopowershell_offensive_tool_keyword = /\\TestNetConnectionCommand\.cs/ nocase ascii wide
                        $string52_nopowershell_offensive_tool_keyword = /\\Tmp\\nc\.exe/ nocase ascii wide
                        $string53_nopowershell_offensive_tool_keyword = /\\Tmp\\netcat\.exe/ nocase ascii wide
                        $string54_nopowershell_offensive_tool_keyword = /\\WhereObjectCommand\.cs/ nocase ascii wide
                        $string55_nopowershell_offensive_tool_keyword = /\\Windows\\System32\\nc\.exe/ nocase ascii wide
                        $string56_nopowershell_offensive_tool_keyword = /\\WriteOutputCommand\.cs/ nocase ascii wide
                        $string57_nopowershell_offensive_tool_keyword = /\=\=\sNoPowerShell\sv.{0,1000}\s\=\=/ nocase ascii wide
                        $string58_nopowershell_offensive_tool_keyword = /\=\=\sNoPowerShell\sv.{0,1000}\s\=\=/ nocase ascii wide
                        $string59_nopowershell_offensive_tool_keyword = "555AD0AC-1FDB-4016-8257-170A74CB2F55" nocase ascii wide
                        $string60_nopowershell_offensive_tool_keyword = "555AD0AC-1FDB-4016-8257-170A74CB2F55" nocase ascii wide
                        $string61_nopowershell_offensive_tool_keyword = "bitsadmin/nopowershell" nocase ascii wide
                        $string62_nopowershell_offensive_tool_keyword = /BOFNET\.Bofs\.Jobs/ nocase ascii wide
                        $string63_nopowershell_offensive_tool_keyword = /bofnet\.cna/ nocase ascii wide
                        $string64_nopowershell_offensive_tool_keyword = /BOFNET\.dll/ nocase ascii wide
                        $string65_nopowershell_offensive_tool_keyword = "bofnet_execute " nocase ascii wide
                        $string66_nopowershell_offensive_tool_keyword = /bofnet_execute\.cpp/ nocase ascii wide
                        $string67_nopowershell_offensive_tool_keyword = /bofnet_execute\.cpp\.x64\.obj/ nocase ascii wide
                        $string68_nopowershell_offensive_tool_keyword = /bofnet_execute\.cpp\.x64\.obj/ nocase ascii wide
                        $string69_nopowershell_offensive_tool_keyword = /bofnet_execute\.cpp\.x86\.obj/ nocase ascii wide
                        $string70_nopowershell_offensive_tool_keyword = /bofnet_execute\.cpp\.x86\.obj/ nocase ascii wide
                        $string71_nopowershell_offensive_tool_keyword = "bofnet_load " nocase ascii wide
                        $string72_nopowershell_offensive_tool_keyword = /GetWhoamiCommand\.cs/ nocase ascii wide
                        $string73_nopowershell_offensive_tool_keyword = /https\:\/\/github\.com\/bitsadmin\// nocase ascii wide
                        $string74_nopowershell_offensive_tool_keyword = /NoPowerShell\.cna/ nocase ascii wide
                        $string75_nopowershell_offensive_tool_keyword = /NoPowerShell\.Commands/ nocase ascii wide
                        $string76_nopowershell_offensive_tool_keyword = /NoPowerShell\.Commands\.Management/ nocase ascii wide
                        $string77_nopowershell_offensive_tool_keyword = /NoPowerShell\.csproj/ nocase ascii wide
                        $string78_nopowershell_offensive_tool_keyword = /NoPowerShell\.dll/ nocase ascii wide
                        $string79_nopowershell_offensive_tool_keyword = /NoPowerShell\.exe/ nocase ascii wide
                        $string80_nopowershell_offensive_tool_keyword = /NoPowerShell\.sln/ nocase ascii wide
                        $string81_nopowershell_offensive_tool_keyword = /NoPowerShell_trunk\.zip/ nocase ascii wide
                        $string82_nopowershell_offensive_tool_keyword = /NoPowerShell32\.dll/ nocase ascii wide
                        $string83_nopowershell_offensive_tool_keyword = /NoPowerShell64\.dll/ nocase ascii wide
                        $string84_nopowershell_offensive_tool_keyword = /NoPowerShellDll\./ nocase ascii wide
                        $string85_nopowershell_offensive_tool_keyword = "nps whoami" nocase ascii wide
                        $string86_nopowershell_offensive_tool_keyword = "PublicKeyToken=8337224c9ad9e356" nocase ascii wide

    condition:
        any of them
}