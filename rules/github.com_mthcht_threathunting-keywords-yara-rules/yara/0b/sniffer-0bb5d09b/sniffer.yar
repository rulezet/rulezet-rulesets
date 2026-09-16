rule sniffer
{
    meta:
        description = "Detection patterns for the tool 'sniffer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sniffer"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/sniffer\.git/ nocase ascii wide
                        $string2 = "brew install sniffer" nocase ascii wide
                        $string3 = "chenjiandongx/sniffer" nocase ascii wide
                        $string4 = /sniffer\-master\.zip/ nocase ascii wide

    condition:
        any of them
}