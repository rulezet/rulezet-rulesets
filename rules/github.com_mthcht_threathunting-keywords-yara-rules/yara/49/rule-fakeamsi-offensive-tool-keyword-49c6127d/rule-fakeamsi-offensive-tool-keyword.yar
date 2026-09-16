rule rule_FakeAMSI_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'FakeAMSI' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "FakeAMSI"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_FakeAMSI_offensive_tool_keyword = /FakeAMSI\.c/ nocase ascii wide
                        $string2_FakeAMSI_offensive_tool_keyword = /FakeAMSI\.dll/ nocase ascii wide
                        $string3_FakeAMSI_offensive_tool_keyword = /FakeAMSI\.exe/ nocase ascii wide

    condition:
        any of them
}