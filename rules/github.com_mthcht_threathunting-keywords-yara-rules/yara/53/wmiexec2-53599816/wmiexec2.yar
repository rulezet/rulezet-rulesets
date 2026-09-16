rule wmiexec2
{
    meta:
        description = "Detection patterns for the tool 'wmiexec2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wmiexec2"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/remoteshell\.py/ nocase ascii wide
                        $string2 = /\/wmiexec2\.git/ nocase ascii wide
                        $string3 = "ice-wzl/wmiexec2" nocase ascii wide
                        $string4 = /wmiexec2\.0\.py/ nocase ascii wide
                        $string5 = /wmiexec2\.py/ nocase ascii wide
                        $string6 = "wmiexec2-main" nocase ascii wide

    condition:
        any of them
}