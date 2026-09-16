rule iNinja_VPN
{
    meta:
        description = "Detection patterns for the tool 'iNinja VPN' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "iNinja VPN"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "ookhnhpkphagefgdiemllfajmkdkcaim" nocase ascii wide

    condition:
        any of them
}