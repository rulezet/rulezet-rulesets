rule rule_Mara_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Mara' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Mara"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Mara_offensive_tool_keyword = /\smain\.c\s\slog\.c\sshelljack\.c\s/ nocase ascii wide
                        $string2_Mara_offensive_tool_keyword = "/io-tl/Mara" nocase ascii wide
                        $string3_Mara_offensive_tool_keyword = /\/Mara\.git/ nocase ascii wide
                        $string4_Mara_offensive_tool_keyword = /\\shelljack\.c/ nocase ascii wide

    condition:
        any of them
}