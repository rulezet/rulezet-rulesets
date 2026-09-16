rule rule_LoGiC_NET_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'LoGiC.NET' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LoGiC.NET"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_LoGiC_NET_offensive_tool_keyword = /AnErrupTion\/LoGiC\.NET/ nocase ascii wide
                        $string2_LoGiC_NET_offensive_tool_keyword = /LoGiC\.NET\.exe/ nocase ascii wide

    condition:
        any of them
}