rule rule_omg_payloads_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'omg-payloads' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "omg-payloads"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_omg_payloads_offensive_tool_keyword = /\/omg\-payloads\.git/ nocase ascii wide
                        $string2_omg_payloads_offensive_tool_keyword = "hak5/omg-payloads" nocase ascii wide
                        $string3_omg_payloads_offensive_tool_keyword = /omg\-payloads.{0,1000}\/payloads\// nocase ascii wide
                        $string4_omg_payloads_offensive_tool_keyword = "omg-payloads-master" nocase ascii wide

    condition:
        any of them
}