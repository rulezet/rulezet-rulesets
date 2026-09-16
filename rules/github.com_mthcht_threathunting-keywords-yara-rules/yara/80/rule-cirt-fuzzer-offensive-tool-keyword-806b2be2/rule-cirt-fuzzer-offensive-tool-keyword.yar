rule rule_cirt_fuzzer_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'cirt-fuzzer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "cirt-fuzzer"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_cirt_fuzzer_offensive_tool_keyword = "cirt-fuzzer" nocase ascii wide

    condition:
        any of them
}