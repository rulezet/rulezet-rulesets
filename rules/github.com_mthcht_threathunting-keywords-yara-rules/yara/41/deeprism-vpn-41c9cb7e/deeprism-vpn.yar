rule DEEPRISM_VPN
{
    meta:
        description = "Detection patterns for the tool 'DEEPRISM VPN' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DEEPRISM VPN"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "bihhflimonbpcfagfadcnbbdngpopnjb" nocase ascii wide

    condition:
        any of them
}