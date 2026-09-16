rule rule_PcapXray_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'PcapXray' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PcapXray"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_PcapXray_offensive_tool_keyword = "PcapXray" nocase ascii wide

    condition:
        any of them
}