rule WindmillVPN
{
    meta:
        description = "Detection patterns for the tool 'WindmillVPN' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WindmillVPN"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "ggackgngljinccllcmbgnpgpllcjepgc" nocase ascii wide

    condition:
        any of them
}