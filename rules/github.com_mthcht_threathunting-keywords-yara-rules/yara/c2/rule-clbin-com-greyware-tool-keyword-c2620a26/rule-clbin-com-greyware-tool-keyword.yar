rule rule_clbin_com_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'clbin.com' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "clbin.com"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_clbin_com_greyware_tool_keyword = /\s\|\sclbin/ nocase ascii wide
                        $string2_clbin_com_greyware_tool_keyword = /https\:\/\/clbin\.com\// nocase ascii wide

    condition:
        any of them
}