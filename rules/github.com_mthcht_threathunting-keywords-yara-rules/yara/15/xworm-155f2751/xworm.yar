rule Xworm
{
    meta:
        description = "Detection patterns for the tool 'Xworm' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Xworm"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/Command\sReciever\.exe/ nocase ascii wide
                        $string2 = /\/Command\%20Reciever\.exe/ nocase ascii wide
                        $string3 = /\/DeleteWD\.dll/ nocase ascii wide
                        $string4 = /\/DisableWD\.dll\,/ nocase ascii wide
                        $string5 = /\/HVNC\-Server\.exe/ nocase ascii wide
                        $string6 = /\/Keylogger\.dll/ nocase ascii wide
                        $string7 = /\/Ngrok\-Disk\.dll/ nocase ascii wide
                        $string8 = /\/Ngrok\-Install\.dll/ nocase ascii wide
                        $string9 = /\/PHVNC\.exe/ nocase ascii wide
                        $string10 = /\/Plugins\/HRDP\.dll/ nocase ascii wide
                        $string11 = /\/Plugins\/HVNC\.dll/ nocase ascii wide
                        $string12 = /\/Plugins\/PreventSleep\.dll/ nocase ascii wide
                        $string13 = /\/Ransomware\.dll/ nocase ascii wide
                        $string14 = /\/Ransomware\.pdb/ nocase ascii wide
                        $string15 = /\/Tools\/ResHacker\.exe/ nocase ascii wide
                        $string16 = /\/UACBypass\.dll/ nocase ascii wide
                        $string17 = /\/WDExclusion\.dll/ nocase ascii wide
                        $string18 = /\/WifiKeys\.dll/ nocase ascii wide
                        $string19 = /\/Worm\.dll/ nocase ascii wide
                        $string20 = /\/XHVNC\.exe/ nocase ascii wide
                        $string21 = /\/XWorm\.exe/ nocase ascii wide
                        $string22 = /\/XWorm\.zip/ nocase ascii wide
                        $string23 = "/XWorm-RAT-V" nocase ascii wide
                        $string24 = /\\Command\sReciever\.exe/ nocase ascii wide
                        $string25 = /\\DeleteWD\.dll/ nocase ascii wide
                        $string26 = /\\DisableWD\.dll\,/ nocase ascii wide
                        $string27 = /\\HVNC\-Server\.exe/ nocase ascii wide
                        $string28 = /\\Keylogger\.dll/ nocase ascii wide
                        $string29 = /\\KillWindows\.dll/ nocase ascii wide
                        $string30 = /\\KillWindows\.pdb/ nocase ascii wide
                        $string31 = /\\Ngrok\-Disk\.dll/ nocase ascii wide
                        $string32 = /\\Ngrok\-Install\.dll/ nocase ascii wide
                        $string33 = /\\PHVNC\.exe/ nocase ascii wide
                        $string34 = /\\PHVNC\.pdb/ nocase ascii wide
                        $string35 = /\\Plugins\\HRDP\.dll/ nocase ascii wide
                        $string36 = /\\Plugins\\HVNC\.dll/ nocase ascii wide
                        $string37 = /\\Plugins\\PreventSleep\.dll/ nocase ascii wide
                        $string38 = /\\Ransomware\.dll/ nocase ascii wide
                        $string39 = /\\Ransomware\.pdb/ nocase ascii wide
                        $string40 = /\\SOFTWARE\\Xworm/ nocase ascii wide
                        $string41 = /\\Tools\\ResHacker\.exe/ nocase ascii wide
                        $string42 = /\\UACBypass\.dll/ nocase ascii wide
                        $string43 = /\\WDExclusion\.dll/ nocase ascii wide
                        $string44 = /\\WDExclusion\.pdb/ nocase ascii wide
                        $string45 = /\\WifiKeys\.dll/ nocase ascii wide
                        $string46 = /\\WifiKeys\.pdb/ nocase ascii wide
                        $string47 = /\\Worm\.dll/ nocase ascii wide
                        $string48 = /\\XHVNC\.exe/ nocase ascii wide
                        $string49 = /\\XWorm\sRAT\sV/ nocase ascii wide
                        $string50 = /\\XWorm\.exe/ nocase ascii wide
                        $string51 = /\\XWorm\.zip/ nocase ascii wide
                        $string52 = /\\XWorm\-RAT\-/ nocase ascii wide
                        $string53 = "23ed5325043d0b9e7a9115792b12817cec836ba09e5af2aab3408606da729681" nocase ascii wide
                        $string54 = "2bd33a784af634af7590ad9dc43d574005dd95b2b2e20640b97cff0474af91c6" nocase ascii wide
                        $string55 = "5b32dad4ad2b350157eda3061dc821645e7cd291970509ab32e9023b8c945951" nocase ascii wide
                        $string56 = "67d9b4b35c02a19ab364ad19e1972645eb98e24dcd6f1715d2a26229deb2ccf5" nocase ascii wide
                        $string57 = "815dfb13e0c4d5040ffb1dde7350cc77f227b2945b01c61bf54f85eefdd182cf" nocase ascii wide
                        $string58 = "995e755827bf8c1908e64d40a7851e05706b89e41dee63037e5c4be0b61f113e" nocase ascii wide
                        $string59 = /Cmstp\-Bypass\.dll/ nocase ascii wide
                        $string60 = /Cmstp\-Bypass\.pdb/ nocase ascii wide
                        $string61 = "d384ec908583b271588a27748850e4cadf9d8b55a4afdfa54170738da54fc4ef" nocase ascii wide
                        $string62 = "e92707537fe99713752f3d3f479fa68a0c8dd80439c13a2bb4ebb36a952b63fd" nocase ascii wide
                        $string63 = "ea912ca7c74d76924cdf1e634164d723a6d7a48212ab03c0f343a0132754a41b" nocase ascii wide
                        $string64 = "ea9258e9975b8925a739066221d996aef19b4ef4f4c91524f82e39d403f25579" nocase ascii wide
                        $string65 = /HVNC\.Properties/ nocase ascii wide
                        $string66 = "If XWorm Does Not work - Run This Script As Administrator!" nocase ascii wide
                        $string67 = /Keylogger\.My/ nocase ascii wide
                        $string68 = /UACBypass\.My/ nocase ascii wide
                        $string69 = /XWorm_RAT_V2\._1\.data\./ nocase ascii wide

    condition:
        any of them
}