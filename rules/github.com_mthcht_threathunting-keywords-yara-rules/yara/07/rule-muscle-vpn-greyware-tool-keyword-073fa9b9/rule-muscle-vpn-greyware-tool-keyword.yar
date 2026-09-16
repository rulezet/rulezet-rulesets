rule rule_Muscle_VPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Muscle VPN' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Muscle VPN"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_Muscle_VPN_greyware_tool_keyword = "edknjdjielmpdlnllkdmaghlbpnmjmgb" nocase ascii wide

    condition:
        any of them
}