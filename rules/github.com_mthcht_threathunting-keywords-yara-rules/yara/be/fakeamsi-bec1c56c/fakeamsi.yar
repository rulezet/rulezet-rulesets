rule FakeAMSI
{
    meta:
        description = "Detection patterns for the tool 'FakeAMSI' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "FakeAMSI"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /FakeAMSI\.c/ nocase ascii wide
                        $string2 = /FakeAMSI\.dll/ nocase ascii wide
                        $string3 = /FakeAMSI\.exe/ nocase ascii wide

    condition:
        any of them
}