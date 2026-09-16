rule rule_Pcredz_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Pcredz' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Pcredz"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Pcredz_offensive_tool_keyword = /\.\/Pcredz\s/
                        $string2_Pcredz_offensive_tool_keyword = "lgandx/Pcredz" nocase ascii wide
                        $string3_Pcredz_offensive_tool_keyword = "Pcredz -d " nocase ascii wide
                        $string4_Pcredz_offensive_tool_keyword = "Pcredz -f " nocase ascii wide
                        $string5_Pcredz_offensive_tool_keyword = "Pcredz -i " nocase ascii wide

    condition:
        any of them
}