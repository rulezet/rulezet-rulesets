rule DUBrute
{
    meta:
        description = "Detection patterns for the tool 'DUBrute' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DUBrute"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/DUBrute\.git/ nocase ascii wide
                        $string2 = "ch0sys/DUBrute" nocase ascii wide
                        $string3 = "Create %d IP@Loginl;Password" nocase ascii wide
                        $string4 = "d53fb2aa459eb50e3d16f17835db3246e3016389cfa63c126263e24fa18729e7" nocase ascii wide
                        $string5 = "DuBrute v" nocase ascii wide
                        $string6 = /dubrute\.exe/ nocase ascii wide
                        $string7 = "DUBrute_v" nocase ascii wide
                        $string8 = "Generator IP@Login;Password" nocase ascii wide
                        $string9 = "Hacked by Skenda Unikkatil" nocase ascii wide

    condition:
        any of them
}