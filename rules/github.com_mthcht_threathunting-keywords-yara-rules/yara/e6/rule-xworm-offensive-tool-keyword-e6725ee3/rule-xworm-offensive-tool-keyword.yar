rule rule_Xworm_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Xworm' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Xworm"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Xworm_offensive_tool_keyword = /\/Command\sReciever\.exe/ nocase ascii wide
                        $string2_Xworm_offensive_tool_keyword = /\/Command\%20Reciever\.exe/ nocase ascii wide
                        $string3_Xworm_offensive_tool_keyword = /\/DeleteWD\.dll/ nocase ascii wide
                        $string4_Xworm_offensive_tool_keyword = /\/DisableWD\.dll\,/ nocase ascii wide
                        $string5_Xworm_offensive_tool_keyword = /\/HVNC\-Server\.exe/ nocase ascii wide
                        $string6_Xworm_offensive_tool_keyword = /\/Keylogger\.dll/ nocase ascii wide
                        $string7_Xworm_offensive_tool_keyword = /\/Ngrok\-Disk\.dll/ nocase ascii wide
                        $string8_Xworm_offensive_tool_keyword = /\/Ngrok\-Install\.dll/ nocase ascii wide
                        $string9_Xworm_offensive_tool_keyword = /\/PHVNC\.exe/ nocase ascii wide
                        $string10_Xworm_offensive_tool_keyword = /\/Plugins\/HRDP\.dll/ nocase ascii wide
                        $string11_Xworm_offensive_tool_keyword = /\/Plugins\/HVNC\.dll/ nocase ascii wide
                        $string12_Xworm_offensive_tool_keyword = /\/Plugins\/PreventSleep\.dll/ nocase ascii wide
                        $string13_Xworm_offensive_tool_keyword = /\/Ransomware\.dll/ nocase ascii wide
                        $string14_Xworm_offensive_tool_keyword = /\/Ransomware\.pdb/ nocase ascii wide
                        $string15_Xworm_offensive_tool_keyword = /\/Tools\/ResHacker\.exe/ nocase ascii wide
                        $string16_Xworm_offensive_tool_keyword = /\/UACBypass\.dll/ nocase ascii wide
                        $string17_Xworm_offensive_tool_keyword = /\/WDExclusion\.dll/ nocase ascii wide
                        $string18_Xworm_offensive_tool_keyword = /\/WifiKeys\.dll/ nocase ascii wide
                        $string19_Xworm_offensive_tool_keyword = /\/Worm\.dll/ nocase ascii wide
                        $string20_Xworm_offensive_tool_keyword = /\/XHVNC\.exe/ nocase ascii wide
                        $string21_Xworm_offensive_tool_keyword = /\/XWorm\.exe/ nocase ascii wide
                        $string22_Xworm_offensive_tool_keyword = /\/XWorm\.zip/ nocase ascii wide
                        $string23_Xworm_offensive_tool_keyword = "/XWorm-RAT-V" nocase ascii wide
                        $string24_Xworm_offensive_tool_keyword = /\\Command\sReciever\.exe/ nocase ascii wide
                        $string25_Xworm_offensive_tool_keyword = /\\DeleteWD\.dll/ nocase ascii wide
                        $string26_Xworm_offensive_tool_keyword = /\\DisableWD\.dll\,/ nocase ascii wide
                        $string27_Xworm_offensive_tool_keyword = /\\HVNC\-Server\.exe/ nocase ascii wide
                        $string28_Xworm_offensive_tool_keyword = /\\Keylogger\.dll/ nocase ascii wide
                        $string29_Xworm_offensive_tool_keyword = /\\KillWindows\.dll/ nocase ascii wide
                        $string30_Xworm_offensive_tool_keyword = /\\KillWindows\.pdb/ nocase ascii wide
                        $string31_Xworm_offensive_tool_keyword = /\\Ngrok\-Disk\.dll/ nocase ascii wide
                        $string32_Xworm_offensive_tool_keyword = /\\Ngrok\-Install\.dll/ nocase ascii wide
                        $string33_Xworm_offensive_tool_keyword = /\\PHVNC\.exe/ nocase ascii wide
                        $string34_Xworm_offensive_tool_keyword = /\\PHVNC\.pdb/ nocase ascii wide
                        $string35_Xworm_offensive_tool_keyword = /\\Plugins\\HRDP\.dll/ nocase ascii wide
                        $string36_Xworm_offensive_tool_keyword = /\\Plugins\\HVNC\.dll/ nocase ascii wide
                        $string37_Xworm_offensive_tool_keyword = /\\Plugins\\PreventSleep\.dll/ nocase ascii wide
                        $string38_Xworm_offensive_tool_keyword = /\\Ransomware\.dll/ nocase ascii wide
                        $string39_Xworm_offensive_tool_keyword = /\\Ransomware\.pdb/ nocase ascii wide
                        $string40_Xworm_offensive_tool_keyword = /\\SOFTWARE\\Xworm/ nocase ascii wide
                        $string41_Xworm_offensive_tool_keyword = /\\Tools\\ResHacker\.exe/ nocase ascii wide
                        $string42_Xworm_offensive_tool_keyword = /\\UACBypass\.dll/ nocase ascii wide
                        $string43_Xworm_offensive_tool_keyword = /\\WDExclusion\.dll/ nocase ascii wide
                        $string44_Xworm_offensive_tool_keyword = /\\WDExclusion\.pdb/ nocase ascii wide
                        $string45_Xworm_offensive_tool_keyword = /\\WifiKeys\.dll/ nocase ascii wide
                        $string46_Xworm_offensive_tool_keyword = /\\WifiKeys\.pdb/ nocase ascii wide
                        $string47_Xworm_offensive_tool_keyword = /\\Worm\.dll/ nocase ascii wide
                        $string48_Xworm_offensive_tool_keyword = /\\XHVNC\.exe/ nocase ascii wide
                        $string49_Xworm_offensive_tool_keyword = /\\XWorm\sRAT\sV/ nocase ascii wide
                        $string50_Xworm_offensive_tool_keyword = /\\XWorm\.exe/ nocase ascii wide
                        $string51_Xworm_offensive_tool_keyword = /\\XWorm\.zip/ nocase ascii wide
                        $string52_Xworm_offensive_tool_keyword = /\\XWorm\-RAT\-/ nocase ascii wide
                        $string53_Xworm_offensive_tool_keyword = "23ed5325043d0b9e7a9115792b12817cec836ba09e5af2aab3408606da729681" nocase ascii wide
                        $string54_Xworm_offensive_tool_keyword = "2bd33a784af634af7590ad9dc43d574005dd95b2b2e20640b97cff0474af91c6" nocase ascii wide
                        $string55_Xworm_offensive_tool_keyword = "5b32dad4ad2b350157eda3061dc821645e7cd291970509ab32e9023b8c945951" nocase ascii wide
                        $string56_Xworm_offensive_tool_keyword = "67d9b4b35c02a19ab364ad19e1972645eb98e24dcd6f1715d2a26229deb2ccf5" nocase ascii wide
                        $string57_Xworm_offensive_tool_keyword = "815dfb13e0c4d5040ffb1dde7350cc77f227b2945b01c61bf54f85eefdd182cf" nocase ascii wide
                        $string58_Xworm_offensive_tool_keyword = "995e755827bf8c1908e64d40a7851e05706b89e41dee63037e5c4be0b61f113e" nocase ascii wide
                        $string59_Xworm_offensive_tool_keyword = /Cmstp\-Bypass\.dll/ nocase ascii wide
                        $string60_Xworm_offensive_tool_keyword = /Cmstp\-Bypass\.pdb/ nocase ascii wide
                        $string61_Xworm_offensive_tool_keyword = "d384ec908583b271588a27748850e4cadf9d8b55a4afdfa54170738da54fc4ef" nocase ascii wide
                        $string62_Xworm_offensive_tool_keyword = "e92707537fe99713752f3d3f479fa68a0c8dd80439c13a2bb4ebb36a952b63fd" nocase ascii wide
                        $string63_Xworm_offensive_tool_keyword = "ea912ca7c74d76924cdf1e634164d723a6d7a48212ab03c0f343a0132754a41b" nocase ascii wide
                        $string64_Xworm_offensive_tool_keyword = "ea9258e9975b8925a739066221d996aef19b4ef4f4c91524f82e39d403f25579" nocase ascii wide
                        $string65_Xworm_offensive_tool_keyword = /HVNC\.Properties/ nocase ascii wide
                        $string66_Xworm_offensive_tool_keyword = "If XWorm Does Not work - Run This Script As Administrator!" nocase ascii wide
                        $string67_Xworm_offensive_tool_keyword = /Keylogger\.My/ nocase ascii wide
                        $string68_Xworm_offensive_tool_keyword = /UACBypass\.My/ nocase ascii wide
                        $string69_Xworm_offensive_tool_keyword = /XWorm_RAT_V2\._1\.data\./ nocase ascii wide

    condition:
        any of them
}