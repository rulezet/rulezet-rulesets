rule BaRMIe
{
    meta:
        description = "Detection patterns for the tool 'BaRMIe' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BaRMIe"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "BaRMIe" nocase ascii wide

    condition:
        any of them
}