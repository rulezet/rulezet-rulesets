rule rule_KerberOPSEC_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'KerberOPSEC' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "KerberOPSEC"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_KerberOPSEC_offensive_tool_keyword = /\/KerberOPSEC\.git/ nocase ascii wide
                        $string2_KerberOPSEC_offensive_tool_keyword = /\\KerberOPSEC\.cs/ nocase ascii wide
                        $string3_KerberOPSEC_offensive_tool_keyword = /\\KerberOPSEC\.sln/ nocase ascii wide
                        $string4_KerberOPSEC_offensive_tool_keyword = /\\RubeusRoast\.cs/ nocase ascii wide
                        $string5_KerberOPSEC_offensive_tool_keyword = /\\wmievasions\.ps1/ nocase ascii wide
                        $string6_KerberOPSEC_offensive_tool_keyword = ">KerberOPSEC</" nocase ascii wide
                        $string7_KerberOPSEC_offensive_tool_keyword = "3D111394-E7F7-40B7-91CB-D24374DB739A" nocase ascii wide
                        $string8_KerberOPSEC_offensive_tool_keyword = "77efc4024d86cf813ea6f93ef2b98dd4ff8bb8a46f0fd145465786690a27b169" nocase ascii wide
                        $string9_KerberOPSEC_offensive_tool_keyword = "996d133f79b2762f547dcd6900326835517586359ffe5f443c40336983a9a2e7" nocase ascii wide
                        $string10_KerberOPSEC_offensive_tool_keyword = "e52f7c5cdfbcfd07c3af1a5d4b192e804f2a29cc1cacff6573ad701cbeb8440a" nocase ascii wide
                        $string11_KerberOPSEC_offensive_tool_keyword = "eff1f6144cbc0b092a09dc06009fc3709c937347d9b5991560588204fc183414" nocase ascii wide
                        $string12_KerberOPSEC_offensive_tool_keyword = "f8184ce6c3b95b88dda27b246cff8039986843082f8689081c97d59161bc878d" nocase ascii wide
                        $string13_KerberOPSEC_offensive_tool_keyword = /KerberOPSEC\.csproj/ nocase ascii wide
                        $string14_KerberOPSEC_offensive_tool_keyword = /KerberOPSEC\.exe/ nocase ascii wide
                        $string15_KerberOPSEC_offensive_tool_keyword = /KerberOPSEC\-x64\.exe/ nocase ascii wide
                        $string16_KerberOPSEC_offensive_tool_keyword = /KerberOPSEC\-x86\.exe/ nocase ascii wide
                        $string17_KerberOPSEC_offensive_tool_keyword = "Luct0r/KerberOPSEC" nocase ascii wide
                        $string18_KerberOPSEC_offensive_tool_keyword = /netsh\.exe\sinterface\sip\sdelete\sarpcache\s\>C\:\\Windows\\TEMP\\ipconfig\.out\s2\>\&1/ nocase ascii wide

    condition:
        any of them
}