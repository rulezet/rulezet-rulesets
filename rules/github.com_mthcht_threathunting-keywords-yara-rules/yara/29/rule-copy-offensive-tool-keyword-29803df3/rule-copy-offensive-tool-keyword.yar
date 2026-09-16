rule rule_copy_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'copy' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "copy"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_copy_offensive_tool_keyword = /copy\s.{0,1000}\.exe\s\\\\.{0,1000}\\c\$\\Windows\\foxprow\.exe/ nocase ascii wide

    condition:
        any of them
}