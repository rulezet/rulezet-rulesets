rule rule_Keethief_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Keethief' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Keethief"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Keethief_offensive_tool_keyword = /\sKeeThief\.ps1/ nocase ascii wide
                        $string2_Keethief_offensive_tool_keyword = /\$KeePassXMLPath\sbackdoored/ nocase ascii wide
                        $string3_Keethief_offensive_tool_keyword = /\$KeePassXMLPath\striggers\sremoved/ nocase ascii wide
                        $string4_Keethief_offensive_tool_keyword = /\/KeeTheft\.exe/ nocase ascii wide
                        $string5_Keethief_offensive_tool_keyword = /\/KeeThief\.git/ nocase ascii wide
                        $string6_Keethief_offensive_tool_keyword = /\/KeeThief\.ps1/ nocase ascii wide
                        $string7_Keethief_offensive_tool_keyword = /\\Get\-FunctionHash\.ps1/ nocase ascii wide
                        $string8_Keethief_offensive_tool_keyword = /\\Get\-PEHeader\.ps1/ nocase ascii wide
                        $string9_Keethief_offensive_tool_keyword = /\\Invoke\-Shellcode\.ps1/ nocase ascii wide
                        $string10_Keethief_offensive_tool_keyword = /\\KeePass\.sln/ nocase ascii wide
                        $string11_Keethief_offensive_tool_keyword = /\\KeeTheft\.config/ nocase ascii wide
                        $string12_Keethief_offensive_tool_keyword = /\\KeeTheft\.exe/ nocase ascii wide
                        $string13_Keethief_offensive_tool_keyword = /\\KeeTheft\.INI/ nocase ascii wide
                        $string14_Keethief_offensive_tool_keyword = /\\KeeThief\.ps1/ nocase ascii wide
                        $string15_Keethief_offensive_tool_keyword = /\\MostPopularPasswords\.txt/ nocase ascii wide
                        $string16_Keethief_offensive_tool_keyword = ">KeeTheft<" nocase ascii wide
                        $string17_Keethief_offensive_tool_keyword = "211446645fa7a934da99f218cc049cd1c59c68ac2a5da2033eaceff80b1d1c0e" nocase ascii wide
                        $string18_Keethief_offensive_tool_keyword = "3d00518d63ef9b656fdef85621d8a4f3137569ea71b07d431da6b39704f54dee" nocase ascii wide
                        $string19_Keethief_offensive_tool_keyword = "3FCA8012-3BAD-41E4-91F4-534AA9A44F96" nocase ascii wide
                        $string20_Keethief_offensive_tool_keyword = "457cd41fbb528812aa51bc4b31fce042cdf736281b162181d91c47733d0e9e4b" nocase ascii wide
                        $string21_Keethief_offensive_tool_keyword = "4969b09ab7cae1ba1f02a509b9b7099195fab22321b73039fcce92e9974d7b93" nocase ascii wide
                        $string22_Keethief_offensive_tool_keyword = "6FC09BDB-365F-4691-BBD9-CB7F69C9527A" nocase ascii wide
                        $string23_Keethief_offensive_tool_keyword = "80BA63A4-7D41-40E9-A722-6DD58B28BF7E" nocase ascii wide
                        $string24_Keethief_offensive_tool_keyword = "935D33C5-62F1-40FE-8DB0-46B6E01342FB" nocase ascii wide
                        $string25_Keethief_offensive_tool_keyword = "a01a3fe8fd6c3ff03908efd3321438df49365d0f64fa0a862419e31112936e3e" nocase ascii wide
                        $string26_Keethief_offensive_tool_keyword = "adbed7685fc512f48cf0edb1eb0df16fed97c52d5eab0fe70e88286c47d53e3d" nocase ascii wide
                        $string27_Keethief_offensive_tool_keyword = "Add-KeePassConfigTrigger " nocase ascii wide
                        $string28_Keethief_offensive_tool_keyword = "Add-KeePassConfigTrigger" nocase ascii wide
                        $string29_Keethief_offensive_tool_keyword = "b0cf4ccee3c06fe7d3c7ff2afbfefbe972f82008ec5b2f8a5e5d5cb9a58861a2" nocase ascii wide
                        $string30_Keethief_offensive_tool_keyword = "c0fdcce36afa206ce080c1b8602ecf18fdc23a207078cb437594d7f674b2a693" nocase ascii wide
                        $string31_Keethief_offensive_tool_keyword = "C23B51C4-2475-4FC6-9B3A-27D0A2B99B0F" nocase ascii wide
                        $string32_Keethief_offensive_tool_keyword = "Could not find address marker in shellcode" nocase ascii wide
                        $string33_Keethief_offensive_tool_keyword = "dbed4217e61d4deba7cfb5aa97aef6687507d9bd990110cc31b0d35ee32acada" nocase ascii wide
                        $string34_Keethief_offensive_tool_keyword = "EA92F1E6-3F34-48F8-8B0A-F2BBC19220EF" nocase ascii wide
                        $string35_Keethief_offensive_tool_keyword = "Error: Could not create a thread for the shellcode" nocase ascii wide
                        $string36_Keethief_offensive_tool_keyword = "Find-KeePassconfig " nocase ascii wide
                        $string37_Keethief_offensive_tool_keyword = "Find-KeePassconfig" nocase ascii wide
                        $string38_Keethief_offensive_tool_keyword = "function Local:Inject-RemoteShellcode " nocase ascii wide
                        $string39_Keethief_offensive_tool_keyword = "GetKcpPasswordInfo" nocase ascii wide
                        $string40_Keethief_offensive_tool_keyword = "Get-KeePassConfigTrigger " nocase ascii wide
                        $string41_Keethief_offensive_tool_keyword = "Get-KeePassConfigTrigger" nocase ascii wide
                        $string42_Keethief_offensive_tool_keyword = "Get-KeePassDatabaseKey " nocase ascii wide
                        $string43_Keethief_offensive_tool_keyword = "Get-KeePassDatabaseKey" nocase ascii wide
                        $string44_Keethief_offensive_tool_keyword = /Get\-PEHeader\.ps1/ nocase ascii wide
                        $string45_Keethief_offensive_tool_keyword = "GhostPack/KeeThief" nocase ascii wide
                        $string46_Keethief_offensive_tool_keyword = "Injecting shellcode into PID: " nocase ascii wide
                        $string47_Keethief_offensive_tool_keyword = "Injecting shellcode into PowerShell" nocase ascii wide
                        $string48_Keethief_offensive_tool_keyword = /Interesting\?\sthere\sare\smultiple\s\.NET\sruntimes\sloaded\sin\sKeePass/ nocase ascii wide
                        $string49_Keethief_offensive_tool_keyword = "Invoke-Shellcode -ProcessId " nocase ascii wide
                        $string50_Keethief_offensive_tool_keyword = /KcpPassword\.cs/ nocase ascii wide
                        $string51_Keethief_offensive_tool_keyword = /KeePassConfig\.ps1/ nocase ascii wide
                        $string52_Keethief_offensive_tool_keyword = /KeePassLib\.Keys\.KcpPassword/ nocase ascii wide
                        $string53_Keethief_offensive_tool_keyword = "KeeThief" nocase ascii wide
                        $string54_Keethief_offensive_tool_keyword = /MSIL\/KeeThief\.A\!tr\.pws/ nocase ascii wide
                        $string55_Keethief_offensive_tool_keyword = /MSIL\/PSW\.KeeThief\.A/ nocase ascii wide
                        $string56_Keethief_offensive_tool_keyword = /ReleaseKeePass\.exe/ nocase ascii wide
                        $string57_Keethief_offensive_tool_keyword = /ReleaseKeeTheft\.exe/ nocase ascii wide
                        $string58_Keethief_offensive_tool_keyword = "Remove-KeePassConfigTrigger" nocase ascii wide
                        $string59_Keethief_offensive_tool_keyword = /Spyware\.KeeThief/ nocase ascii wide

    condition:
        any of them
}