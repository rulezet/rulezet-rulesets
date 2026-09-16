rule rule_fuzz_txt_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'fuzz.txt' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "fuzz.txt"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_fuzz_txt_offensive_tool_keyword = /\/fuzz\.txt/ nocase ascii wide

    condition:
        any of them
}