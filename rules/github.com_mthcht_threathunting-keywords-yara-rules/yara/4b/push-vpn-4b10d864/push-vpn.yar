rule Push_VPN
{
    meta:
        description = "Detection patterns for the tool 'Push VPN' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Push VPN"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "eidnihaadmmancegllknfbliaijfmkgo" nocase ascii wide

    condition:
        any of them
}