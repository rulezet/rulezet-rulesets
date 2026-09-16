rule rule_nps_payload_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'nps_payload' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nps_payload"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_nps_payload_offensive_tool_keyword = /\/nps_payload\.git/ nocase ascii wide
                        $string2_nps_payload_offensive_tool_keyword = /msf_payload\.ps1/ nocase ascii wide
                        $string3_nps_payload_offensive_tool_keyword = "nps_payload" nocase ascii wide
                        $string4_nps_payload_offensive_tool_keyword = /nps_payload\.py/ nocase ascii wide
                        $string5_nps_payload_offensive_tool_keyword = "nps_payload-master" nocase ascii wide

    condition:
        any of them
}