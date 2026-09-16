rule rule_googleweblight_com_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'googleweblight.com' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "googleweblight.com"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_googleweblight_com_greyware_tool_keyword = /https\:\/\/googleweblight\.com\/i\?u\=.{0,1000}ipfs\..{0,1000}\.html/ nocase ascii wide

    condition:
        any of them
}