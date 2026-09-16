rule rule_kubesploit_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'kubesploit' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "kubesploit"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_kubesploit_offensive_tool_keyword = /\/kubesploit\.git/ nocase ascii wide
                        $string2_kubesploit_offensive_tool_keyword = /\/merlin\.dll/ nocase ascii wide
                        $string3_kubesploit_offensive_tool_keyword = /aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\.exe/ nocase ascii wide
                        $string4_kubesploit_offensive_tool_keyword = /bin\/dll\/merlin\.c/ nocase ascii wide
                        $string5_kubesploit_offensive_tool_keyword = "c1090dbc-f2f7-4d90-a241-86e0c0217786" nocase ascii wide
                        $string6_kubesploit_offensive_tool_keyword = /c2endpoint\.php/ nocase ascii wide
                        $string7_kubesploit_offensive_tool_keyword = "cmd/merlinagent/" nocase ascii wide
                        $string8_kubesploit_offensive_tool_keyword = "cmd/merlinagentdll/" nocase ascii wide
                        $string9_kubesploit_offensive_tool_keyword = "cyberark/kubesploit" nocase ascii wide
                        $string10_kubesploit_offensive_tool_keyword = /DisableRealtimeMonitoring\s\$true/ nocase ascii wide
                        $string11_kubesploit_offensive_tool_keyword = /html\/scripts\/merlin\.js/ nocase ascii wide
                        $string12_kubesploit_offensive_tool_keyword = "Invoke-ADSBackdoor" nocase ascii wide
                        $string13_kubesploit_offensive_tool_keyword = /Invoke\-Merlin\.ps1/ nocase ascii wide
                        $string14_kubesploit_offensive_tool_keyword = /Invoke\-ReflectivePEInjection\.ps1/ nocase ascii wide
                        $string15_kubesploit_offensive_tool_keyword = "Joey is the best hacker in Hackers" nocase ascii wide
                        $string16_kubesploit_offensive_tool_keyword = /kubeletAttack\.json/ nocase ascii wide
                        $string17_kubesploit_offensive_tool_keyword = "Kubesploit Agent" nocase ascii wide
                        $string18_kubesploit_offensive_tool_keyword = "kubesploitAgent-Darwin"
                        $string19_kubesploit_offensive_tool_keyword = "kubesploitAgent-Linux"
                        $string20_kubesploit_offensive_tool_keyword = "kubesploit-main" nocase ascii wide
                        $string21_kubesploit_offensive_tool_keyword = "kubesploitServer-Darwin"
                        $string22_kubesploit_offensive_tool_keyword = "kubesploitServer-Linux"
                        $string23_kubesploit_offensive_tool_keyword = /M\.i\.m\.i\.k\.a\.t\.z/ nocase ascii wide
                        $string24_kubesploit_offensive_tool_keyword = /Merlin_v0\.1Beta\.zip/ nocase ascii wide
                        $string25_kubesploit_offensive_tool_keyword = /merlinAgent\.exe/ nocase ascii wide
                        $string26_kubesploit_offensive_tool_keyword = /merlinAgent\-Windows\-x64\.exe/ nocase ascii wide
                        $string27_kubesploit_offensive_tool_keyword = /MerlinCheatSheet\.pdf/ nocase ascii wide
                        $string28_kubesploit_offensive_tool_keyword = /merlinserver\.go/ nocase ascii wide
                        $string29_kubesploit_offensive_tool_keyword = /merlinserver_windows_x64\.exe/ nocase ascii wide
                        $string30_kubesploit_offensive_tool_keyword = /merlinServerLog\.txt/ nocase ascii wide
                        $string31_kubesploit_offensive_tool_keyword = /Password.{0,1000}Winter2017/ nocase ascii wide
                        $string32_kubesploit_offensive_tool_keyword = "Verified Merlin server " nocase ascii wide
                        $string33_kubesploit_offensive_tool_keyword = "xZF7fvaGD6p2yeLyf9i7O9gBBHk05B0u" nocase ascii wide

    condition:
        any of them
}