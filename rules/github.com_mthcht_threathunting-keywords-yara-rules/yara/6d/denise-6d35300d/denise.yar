rule DeNiSe
{
    meta:
        description = "Detection patterns for the tool 'DeNiSe' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DeNiSe"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/DeNiSe\.git/ nocase ascii wide
                        $string2 = /DeNiSe\-master\.zip/ nocase ascii wide
                        $string3 = /DeNiSePkg\.py/ nocase ascii wide
                        $string4 = /dnslog\-\-airvent\.txt/ nocase ascii wide
                        $string5 = "mdornseif/DeNiSe" nocase ascii wide

    condition:
        any of them
}