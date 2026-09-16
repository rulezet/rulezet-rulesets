rule rule_burrow_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'burrow' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "burrow"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_burrow_greyware_tool_keyword = /https\:\/\/burrow\.io\/.{0,1000}\s\|\sbash\s/
                        $string2_burrow_greyware_tool_keyword = /https\:\/\/burrow\.io\/tunnels/ nocase ascii wide

    condition:
        any of them
}