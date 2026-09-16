rule rule_dsniff_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'dsniff' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dsniff"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_dsniff_offensive_tool_keyword = /\/dnsspoof\.c/
                        $string2_dsniff_offensive_tool_keyword = /\/dsniff\.c/
                        $string3_dsniff_offensive_tool_keyword = /\/dsniff\.services/
                        $string4_dsniff_offensive_tool_keyword = "tecknicaltom/dsniff" nocase ascii wide

    condition:
        any of them
}