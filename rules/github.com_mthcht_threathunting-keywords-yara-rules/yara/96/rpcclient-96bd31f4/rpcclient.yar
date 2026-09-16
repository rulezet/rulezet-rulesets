rule rpcclient
{
    meta:
        description = "Detection patterns for the tool 'rpcclient' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "rpcclient"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "rpcclient -U \"\" " nocase ascii wide

    condition:
        any of them
}