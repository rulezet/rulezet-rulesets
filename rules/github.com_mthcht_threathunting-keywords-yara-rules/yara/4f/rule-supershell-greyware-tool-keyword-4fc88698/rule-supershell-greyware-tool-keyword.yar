rule rule_supershell_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'supershell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "supershell"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_supershell_greyware_tool_keyword = "http://localhost:7681" nocase ascii wide
                        $string2_supershell_greyware_tool_keyword = /ttyd\s\-i\s0\.0\.0\.0\s\-p\s7681\s/ nocase ascii wide
                        $string3_supershell_greyware_tool_keyword = /ttyd\s\-i\s0\.0\.0\.0\s\-p\s7682\s/ nocase ascii wide

    condition:
        any of them
}