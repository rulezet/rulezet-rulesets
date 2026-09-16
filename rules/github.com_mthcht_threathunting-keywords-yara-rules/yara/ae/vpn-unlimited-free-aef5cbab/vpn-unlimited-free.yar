rule VPN_Unlimited_Free
{
    meta:
        description = "Detection patterns for the tool 'VPN Unlimited Free' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "VPN Unlimited Free"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "mpcaainmfjjigeicjnlkdfajbioopjko" nocase ascii wide

    condition:
        any of them
}