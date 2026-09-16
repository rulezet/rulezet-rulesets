rule Turbo_VPN_for_PC
{
    meta:
        description = "Detection patterns for the tool 'Turbo VPN for PC' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Turbo VPN for PC"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "jliodmnojccaloajphkingdnpljdhdok" nocase ascii wide

    condition:
        any of them
}