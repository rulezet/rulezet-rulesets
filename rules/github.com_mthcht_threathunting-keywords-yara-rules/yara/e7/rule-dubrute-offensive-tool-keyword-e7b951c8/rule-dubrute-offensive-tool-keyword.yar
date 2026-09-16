rule rule_DUBrute_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'DUBrute' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DUBrute"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_DUBrute_offensive_tool_keyword = /\/DUBrute\.git/ nocase ascii wide
                        $string2_DUBrute_offensive_tool_keyword = "ch0sys/DUBrute" nocase ascii wide
                        $string3_DUBrute_offensive_tool_keyword = "Create %d IP@Loginl;Password" nocase ascii wide
                        $string4_DUBrute_offensive_tool_keyword = "d53fb2aa459eb50e3d16f17835db3246e3016389cfa63c126263e24fa18729e7" nocase ascii wide
                        $string5_DUBrute_offensive_tool_keyword = "DuBrute v" nocase ascii wide
                        $string6_DUBrute_offensive_tool_keyword = /dubrute\.exe/ nocase ascii wide
                        $string7_DUBrute_offensive_tool_keyword = "DUBrute_v" nocase ascii wide
                        $string8_DUBrute_offensive_tool_keyword = "Generator IP@Login;Password" nocase ascii wide
                        $string9_DUBrute_offensive_tool_keyword = "Hacked by Skenda Unikkatil" nocase ascii wide

    condition:
        any of them
}