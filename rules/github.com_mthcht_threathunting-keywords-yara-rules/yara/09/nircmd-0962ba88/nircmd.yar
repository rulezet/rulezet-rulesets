rule nircmd
{
    meta:
        description = "Detection patterns for the tool 'nircmd' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nircmd"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\.exe\selevatecmd\srunassystem\s/ nocase ascii wide
                        $string2 = /\.exe\sexec\shide\s/ nocase ascii wide
                        $string3 = /nircmdc\.exe\ssavescreenshot/ nocase ascii wide

    condition:
        any of them
}