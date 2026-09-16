rule rule_APCLdr_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'APCLdr' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "APCLdr"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_APCLdr_offensive_tool_keyword = /\/APCLdr\./ nocase ascii wide
                        $string2_APCLdr_offensive_tool_keyword = /\\APCLdr\./ nocase ascii wide
                        $string3_APCLdr_offensive_tool_keyword = "NUL0x4C/APCLdr" nocase ascii wide

    condition:
        any of them
}