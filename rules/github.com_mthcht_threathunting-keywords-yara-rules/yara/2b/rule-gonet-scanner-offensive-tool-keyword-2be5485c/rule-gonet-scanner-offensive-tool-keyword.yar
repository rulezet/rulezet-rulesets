rule rule_GONET_Scanner_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'GONET-Scanner' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GONET-Scanner"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_GONET_Scanner_offensive_tool_keyword = "/GONET-Scanner/" nocase ascii wide
                        $string2_GONET_Scanner_offensive_tool_keyword = /\/scannerPort\.go/ nocase ascii wide
                        $string3_GONET_Scanner_offensive_tool_keyword = /go\srun\sscannerPort\.go/ nocase ascii wide
                        $string4_GONET_Scanner_offensive_tool_keyword = /scannerport\.go\s\-/ nocase ascii wide

    condition:
        any of them
}