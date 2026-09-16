rule rule_WMIPersistence_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'WMIPersistence' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WMIPersistence"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_WMIPersistence_offensive_tool_keyword = /\/WMIPersistence\.git/ nocase ascii wide
                        $string2_WMIPersistence_offensive_tool_keyword = "b236ff16fc6a017c5a84d0cc7969e0513636f37058b2b74a95d632ea26953586" nocase ascii wide
                        $string3_WMIPersistence_offensive_tool_keyword = "mdsecactivebreach/WMIPersistence" nocase ascii wide
                        $string4_WMIPersistence_offensive_tool_keyword = /WMIPersist\./ nocase ascii wide

    condition:
        any of them
}