rule rule_SetupVPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SetupVPN' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SetupVPN"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_SetupVPN_greyware_tool_keyword = "oofgbpoabipfcfjapgnbbjjaenockbdp" nocase ascii wide

    condition:
        any of them
}