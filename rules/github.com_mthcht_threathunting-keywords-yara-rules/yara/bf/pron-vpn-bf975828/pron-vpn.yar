rule Pron_VPN
{
    meta:
        description = "Detection patterns for the tool 'Pron VPN' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Pron VPN"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "nhfjkakglbnnpkpldhjmpmmfefifedcj" nocase ascii wide

    condition:
        any of them
}