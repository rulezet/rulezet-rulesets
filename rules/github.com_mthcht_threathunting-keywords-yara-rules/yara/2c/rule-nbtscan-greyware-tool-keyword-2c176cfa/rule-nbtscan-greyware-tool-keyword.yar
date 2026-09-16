rule rule_nbtscan_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'nbtscan' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nbtscan"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_nbtscan_greyware_tool_keyword = /nbtscan\s.{0,1000}\..{0,1000}\/24/ nocase ascii wide
                        $string2_nbtscan_greyware_tool_keyword = /nbtscan\s\-r\s.{0,1000}\/24/ nocase ascii wide
                        $string3_nbtscan_greyware_tool_keyword = "nbtscan -s : " nocase ascii wide

    condition:
        any of them
}