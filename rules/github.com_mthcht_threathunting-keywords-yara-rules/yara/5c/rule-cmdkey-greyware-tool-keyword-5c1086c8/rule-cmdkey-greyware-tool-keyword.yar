rule rule_Cmdkey_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Cmdkey' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Cmdkey"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_Cmdkey_greyware_tool_keyword = /\\cmdkey\.exe\\"\s\/list/ nocase ascii wide
                        $string2_Cmdkey_greyware_tool_keyword = "Cmdkey /list" nocase ascii wide

    condition:
        any of them
}