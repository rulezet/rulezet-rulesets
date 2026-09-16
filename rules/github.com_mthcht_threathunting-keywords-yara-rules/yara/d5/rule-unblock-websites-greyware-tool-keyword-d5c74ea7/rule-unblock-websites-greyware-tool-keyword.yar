rule rule_Unblock_Websites_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Unblock Websites' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Unblock Websites"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_Unblock_Websites_greyware_tool_keyword = "gbmdmipapolaohpinhblmcnpmmlgfgje" nocase ascii wide

    condition:
        any of them
}