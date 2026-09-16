rule rule_wifite2_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'wifite2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wifite2"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_wifite2_offensive_tool_keyword = "/wifite -c " nocase ascii wide
                        $string2_wifite2_offensive_tool_keyword = "/wifite2" nocase ascii wide
                        $string3_wifite2_offensive_tool_keyword = "wifite --crack" nocase ascii wide
                        $string4_wifite2_offensive_tool_keyword = "wifite -e " nocase ascii wide
                        $string5_wifite2_offensive_tool_keyword = "wifite --wep " nocase ascii wide
                        $string6_wifite2_offensive_tool_keyword = /Wifite\.py/ nocase ascii wide
                        $string7_wifite2_offensive_tool_keyword = /wifite2\.git/ nocase ascii wide

    condition:
        any of them
}