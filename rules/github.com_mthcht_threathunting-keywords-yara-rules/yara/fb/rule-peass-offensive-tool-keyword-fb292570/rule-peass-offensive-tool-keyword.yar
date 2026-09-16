rule rule_PEASS_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'PEASS' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PEASS"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_PEASS_offensive_tool_keyword = " import LinpeasBaseBuilder" nocase ascii wide
                        $string2_PEASS_offensive_tool_keyword = " import LinpeasBuilder" nocase ascii wide
                        $string3_PEASS_offensive_tool_keyword = " import PEASLoaded" nocase ascii wide
                        $string4_PEASS_offensive_tool_keyword = " import PEASRecord" nocase ascii wide
                        $string5_PEASS_offensive_tool_keyword = /\slinpeas\.sh\s/
                        $string6_PEASS_offensive_tool_keyword = " -linpeas=http://" nocase ascii wide
                        $string7_PEASS_offensive_tool_keyword = /\s\-linpeas\=http\:\/\/127\.0\.0\.1\/linpeas\.sh/ nocase ascii wide
                        $string8_PEASS_offensive_tool_keyword = " WinPEAS - Windows local Privilege Escalation Awesome Script" nocase ascii wide
                        $string9_PEASS_offensive_tool_keyword = /\.exe\s\s\-lolbas\slog/ nocase ascii wide
                        $string10_PEASS_offensive_tool_keyword = /\/linpeas\.sh/ nocase ascii wide
                        $string11_PEASS_offensive_tool_keyword = /\/linpeas\.sh/ nocase ascii wide
                        $string12_PEASS_offensive_tool_keyword = /\/linpeas\.txt/ nocase ascii wide
                        $string13_PEASS_offensive_tool_keyword = /\/linpeasBaseBuilder\.py/ nocase ascii wide
                        $string14_PEASS_offensive_tool_keyword = /\/linpeasBuilder\.py/ nocase ascii wide
                        $string15_PEASS_offensive_tool_keyword = /\/PEASS\-ng\.git/ nocase ascii wide
                        $string16_PEASS_offensive_tool_keyword = "/PEASS-ng/" nocase ascii wide
                        $string17_PEASS_offensive_tool_keyword = /\[\+\]\sBuilding\sGTFOBins\slists/ nocase ascii wide
                        $string18_PEASS_offensive_tool_keyword = /\[\+\]\sBuilding\slinux\sexploit\ssuggesters/
                        $string19_PEASS_offensive_tool_keyword = /\[\+\]\sDownloading\sFat\sLinpeas\sbinaries/ nocase ascii wide
                        $string20_PEASS_offensive_tool_keyword = /\\PEASS\-ng/ nocase ascii wide
                        $string21_PEASS_offensive_tool_keyword = /\\winPEAS\.sln/ nocase ascii wide
                        $string22_PEASS_offensive_tool_keyword = /\\winPEASexe\\/ nocase ascii wide
                        $string23_PEASS_offensive_tool_keyword = "66AA4619-4D0F-4226-9D96-298870E9BB50" nocase ascii wide
                        $string24_PEASS_offensive_tool_keyword = "builder/linpeas_parts/" nocase ascii wide
                        $string25_PEASS_offensive_tool_keyword = "D934058E-A7DB-493F-A741-AE8E3DF867F4" nocase ascii wide
                        $string26_PEASS_offensive_tool_keyword = /gather\/peass\.rb/ nocase ascii wide
                        $string27_PEASS_offensive_tool_keyword = /linpeas_builder\.py/ nocase ascii wide
                        $string28_PEASS_offensive_tool_keyword = "linpeas_darwin_amd64"
                        $string29_PEASS_offensive_tool_keyword = "linpeas_darwin_arm64"
                        $string30_PEASS_offensive_tool_keyword = /linpeas_fat\.sh/ nocase ascii wide
                        $string31_PEASS_offensive_tool_keyword = "linpeas_linux_386"
                        $string32_PEASS_offensive_tool_keyword = "linpeas_linux_amd64"
                        $string33_PEASS_offensive_tool_keyword = "linpeas_linux_arm64"
                        $string34_PEASS_offensive_tool_keyword = /metasploit\/peass\.rb/ nocase ascii wide
                        $string35_PEASS_offensive_tool_keyword = "PEASS-ng-master" nocase ascii wide
                        $string36_PEASS_offensive_tool_keyword = /winPEAS\.bat/ nocase ascii wide
                        $string37_PEASS_offensive_tool_keyword = /WinPEAS\.exe/ nocase ascii wide
                        $string38_PEASS_offensive_tool_keyword = /winPEAS\.ps1/ nocase ascii wide
                        $string39_PEASS_offensive_tool_keyword = /winPEASany\.exe/ nocase ascii wide
                        $string40_PEASS_offensive_tool_keyword = /winPEASany_ofs\.exe/ nocase ascii wide
                        $string41_PEASS_offensive_tool_keyword = "winPEAS-Obfuscated" nocase ascii wide
                        $string42_PEASS_offensive_tool_keyword = "winPEASps1" nocase ascii wide
                        $string43_PEASS_offensive_tool_keyword = /winPEASx64\.exe/ nocase ascii wide
                        $string44_PEASS_offensive_tool_keyword = /winPEASx64_ofs\.exe/ nocase ascii wide
                        $string45_PEASS_offensive_tool_keyword = /winPEASx86\.exe/ nocase ascii wide
                        $string46_PEASS_offensive_tool_keyword = /winPEASx86_ofs\.exe/ nocase ascii wide

    condition:
        any of them
}