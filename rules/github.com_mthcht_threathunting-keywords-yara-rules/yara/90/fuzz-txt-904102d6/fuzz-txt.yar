rule fuzz_txt
{
    meta:
        description = "Detection patterns for the tool 'fuzz.txt' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "fuzz.txt"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/fuzz\.txt/ nocase ascii wide

    condition:
        any of them
}