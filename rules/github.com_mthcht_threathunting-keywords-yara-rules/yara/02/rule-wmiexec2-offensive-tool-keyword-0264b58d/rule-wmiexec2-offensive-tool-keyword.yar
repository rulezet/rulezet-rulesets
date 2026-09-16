rule rule_wmiexec2_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'wmiexec2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wmiexec2"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_wmiexec2_offensive_tool_keyword = /\/remoteshell\.py/ nocase ascii wide
                        $string2_wmiexec2_offensive_tool_keyword = /\/wmiexec2\.git/ nocase ascii wide
                        $string3_wmiexec2_offensive_tool_keyword = "ice-wzl/wmiexec2" nocase ascii wide
                        $string4_wmiexec2_offensive_tool_keyword = /wmiexec2\.0\.py/ nocase ascii wide
                        $string5_wmiexec2_offensive_tool_keyword = /wmiexec2\.py/ nocase ascii wide
                        $string6_wmiexec2_offensive_tool_keyword = "wmiexec2-main" nocase ascii wide

    condition:
        any of them
}