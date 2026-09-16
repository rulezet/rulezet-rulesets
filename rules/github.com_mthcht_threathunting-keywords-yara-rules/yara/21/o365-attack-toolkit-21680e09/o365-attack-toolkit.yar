rule o365_attack_toolkit
{
    meta:
        description = "Detection patterns for the tool 'o365-attack-toolkit' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "o365-attack-toolkit"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "f96865aaead8186eba43688e85b6632375f4f058dd1f867152fbc7b6d64344dd" nocase ascii wide
                        $string2 = "o365-attack-toolkit" nocase ascii wide

    condition:
        any of them
}