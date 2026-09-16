rule rule_p0f_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'p0f' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "p0f"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_p0f_offensive_tool_keyword = /\/tmp\/p0f\.log/
                        $string2_p0f_offensive_tool_keyword = "install p0f" nocase ascii wide
                        $string3_p0f_offensive_tool_keyword = /p0f\s\-i\seth.{0,1000}\s\-p/ nocase ascii wide
                        $string4_p0f_offensive_tool_keyword = /p0f\/p0f\.fp/ nocase ascii wide

    condition:
        any of them
}