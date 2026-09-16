rule Upnet
{
    meta:
        description = "Detection patterns for the tool 'Upnet' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Upnet"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "bniikohfmajhdcffljgfeiklcbgffppl" nocase ascii wide

    condition:
        any of them
}