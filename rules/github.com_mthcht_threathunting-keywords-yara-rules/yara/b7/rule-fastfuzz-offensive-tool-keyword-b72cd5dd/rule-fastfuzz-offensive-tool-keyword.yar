rule rule_fastfuzz_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'fastfuzz' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "fastfuzz"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_fastfuzz_offensive_tool_keyword = "/fastfuz-chrome-ext" nocase ascii wide
                        $string2_fastfuzz_offensive_tool_keyword = /fastfuz\-chrome\-ext.{0,1000}files\.txt/ nocase ascii wide

    condition:
        any of them
}