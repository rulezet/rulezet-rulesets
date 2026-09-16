rule Unblock_Websites
{
    meta:
        description = "Detection patterns for the tool 'Unblock Websites' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Unblock Websites"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "gbmdmipapolaohpinhblmcnpmmlgfgje" nocase ascii wide

    condition:
        any of them
}