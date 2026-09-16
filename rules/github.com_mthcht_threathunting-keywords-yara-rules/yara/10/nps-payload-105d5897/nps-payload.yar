rule nps_payload
{
    meta:
        description = "Detection patterns for the tool 'nps_payload' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nps_payload"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/nps_payload\.git/ nocase ascii wide
                        $string2 = /msf_payload\.ps1/ nocase ascii wide
                        $string3 = "nps_payload" nocase ascii wide
                        $string4 = /nps_payload\.py/ nocase ascii wide
                        $string5 = "nps_payload-master" nocase ascii wide

    condition:
        any of them
}