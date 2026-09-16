rule rule_DeNiSe_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'DeNiSe' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DeNiSe"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_DeNiSe_offensive_tool_keyword = /\/DeNiSe\.git/ nocase ascii wide
                        $string2_DeNiSe_offensive_tool_keyword = /DeNiSe\-master\.zip/ nocase ascii wide
                        $string3_DeNiSe_offensive_tool_keyword = /DeNiSePkg\.py/ nocase ascii wide
                        $string4_DeNiSe_offensive_tool_keyword = /dnslog\-\-airvent\.txt/ nocase ascii wide
                        $string5_DeNiSe_offensive_tool_keyword = "mdornseif/DeNiSe" nocase ascii wide

    condition:
        any of them
}