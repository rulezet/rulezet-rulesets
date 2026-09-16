rule rule_nircmd_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'nircmd' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nircmd"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_nircmd_offensive_tool_keyword = /\.exe\selevatecmd\srunassystem\s/ nocase ascii wide
                        $string2_nircmd_offensive_tool_keyword = /\.exe\sexec\shide\s/ nocase ascii wide
                        $string3_nircmd_offensive_tool_keyword = /nircmdc\.exe\ssavescreenshot/ nocase ascii wide

    condition:
        any of them
}