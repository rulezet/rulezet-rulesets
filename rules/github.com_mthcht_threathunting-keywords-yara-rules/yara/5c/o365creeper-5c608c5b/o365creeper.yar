rule o365creeper
{
    meta:
        description = "Detection patterns for the tool 'o365creeper' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "o365creeper"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "261a166e7f42a53510b2ee2faa1178302e3c83887dc138dc32415c77b22a1bd4" nocase ascii wide
                        $string2 = "LMGsec/o365creeper" nocase ascii wide
                        $string3 = /o365creeper\.git/ nocase ascii wide
                        $string4 = /o365creeper\.py/ nocase ascii wide
                        $string5 = "o365creeper-master" nocase ascii wide

    condition:
        any of them
}