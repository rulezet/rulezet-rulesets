rule rule_chashell_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'chashell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "chashell"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_chashell_offensive_tool_keyword = /\/chashell\.git/ nocase ascii wide
                        $string2_chashell_offensive_tool_keyword = "release/chaserv" nocase ascii wide
                        $string3_chashell_offensive_tool_keyword = "release/chashell_" nocase ascii wide
                        $string4_chashell_offensive_tool_keyword = "sysdream/chashell" nocase ascii wide

    condition:
        any of them
}