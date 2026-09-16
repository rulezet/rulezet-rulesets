rule kubesploit
{
    meta:
        description = "Detection patterns for the tool 'kubesploit' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "kubesploit"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/kubesploit\.git/ nocase ascii wide
                        $string2 = /\/merlin\.dll/ nocase ascii wide
                        $string3 = /aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\.exe/ nocase ascii wide
                        $string4 = /bin\/dll\/merlin\.c/ nocase ascii wide
                        $string5 = "c1090dbc-f2f7-4d90-a241-86e0c0217786" nocase ascii wide
                        $string6 = /c2endpoint\.php/ nocase ascii wide
                        $string7 = "cmd/merlinagent/" nocase ascii wide
                        $string8 = "cmd/merlinagentdll/" nocase ascii wide
                        $string9 = "cyberark/kubesploit" nocase ascii wide
                        $string10 = /DisableRealtimeMonitoring\s\$true/ nocase ascii wide
                        $string11 = /html\/scripts\/merlin\.js/ nocase ascii wide
                        $string12 = "Invoke-ADSBackdoor" nocase ascii wide
                        $string13 = /Invoke\-Merlin\.ps1/ nocase ascii wide
                        $string14 = /Invoke\-ReflectivePEInjection\.ps1/ nocase ascii wide
                        $string15 = "Joey is the best hacker in Hackers" nocase ascii wide
                        $string16 = /kubeletAttack\.json/ nocase ascii wide
                        $string17 = "Kubesploit Agent" nocase ascii wide
                        $string18 = "kubesploitAgent-Darwin"
                        $string19 = "kubesploitAgent-Linux"
                        $string20 = "kubesploit-main" nocase ascii wide
                        $string21 = "kubesploitServer-Darwin"
                        $string22 = "kubesploitServer-Linux"
                        $string23 = /M\.i\.m\.i\.k\.a\.t\.z/ nocase ascii wide
                        $string24 = /Merlin_v0\.1Beta\.zip/ nocase ascii wide
                        $string25 = /merlinAgent\.exe/ nocase ascii wide
                        $string26 = /merlinAgent\-Windows\-x64\.exe/ nocase ascii wide
                        $string27 = /MerlinCheatSheet\.pdf/ nocase ascii wide
                        $string28 = /merlinserver\.go/ nocase ascii wide
                        $string29 = /merlinserver_windows_x64\.exe/ nocase ascii wide
                        $string30 = /merlinServerLog\.txt/ nocase ascii wide
                        $string31 = /Password.{0,1000}Winter2017/ nocase ascii wide
                        $string32 = "Verified Merlin server " nocase ascii wide
                        $string33 = "xZF7fvaGD6p2yeLyf9i7O9gBBHk05B0u" nocase ascii wide

    condition:
        any of them
}