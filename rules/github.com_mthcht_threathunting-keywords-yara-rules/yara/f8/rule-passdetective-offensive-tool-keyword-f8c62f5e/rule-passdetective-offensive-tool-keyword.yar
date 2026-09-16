rule rule_PassDetective_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'PassDetective' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PassDetective"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_PassDetective_offensive_tool_keyword = " extract --secrets --zsh" nocase ascii wide
                        $string2_PassDetective_offensive_tool_keyword = /\.\/Passdetective/
                        $string3_PassDetective_offensive_tool_keyword = /\/PassDetective\.git/ nocase ascii wide
                        $string4_PassDetective_offensive_tool_keyword = "aydinnyunus/PassDetective" nocase ascii wide
                        $string5_PassDetective_offensive_tool_keyword = "PassDetective extract" nocase ascii wide
                        $string6_PassDetective_offensive_tool_keyword = /PassDetective\-main\./ nocase ascii wide

    condition:
        any of them
}