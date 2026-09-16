rule GONET_Scanner
{
    meta:
        description = "Detection patterns for the tool 'GONET-Scanner' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GONET-Scanner"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/GONET-Scanner/" nocase ascii wide
                        $string2 = /\/scannerPort\.go/ nocase ascii wide
                        $string3 = /go\srun\sscannerPort\.go/ nocase ascii wide
                        $string4 = /scannerport\.go\s\-/ nocase ascii wide

    condition:
        any of them
}