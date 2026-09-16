rule rule_VirusTotalC2_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'VirusTotalC2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "VirusTotalC2"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_VirusTotalC2_offensive_tool_keyword = "/VirusTotalC2/" nocase ascii wide
                        $string2_VirusTotalC2_offensive_tool_keyword = /Implant.{0,1000}TeamServer\.exe/ nocase ascii wide
                        $string3_VirusTotalC2_offensive_tool_keyword = /VirusTotalC2\./ nocase ascii wide

    condition:
        any of them
}