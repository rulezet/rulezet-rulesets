rule rule_nirsoft_tools_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'nirsoft tools' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nirsoft tools"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_nirsoft_tools_greyware_tool_keyword = /https\:\/\/www\.nirsoft\.net\/toolsdownload\// nocase ascii wide
                        $string2_nirsoft_tools_greyware_tool_keyword = /https\:\/\/www\.nirsoft\.net\/toolsdownload\/.{0,1000}\.exe/ nocase ascii wide
                        $string3_nirsoft_tools_greyware_tool_keyword = /https\:\/\/www\.nirsoft\.net\/toolsdownload\/.{0,1000}\.zip/ nocase ascii wide
                        $string4_nirsoft_tools_greyware_tool_keyword = /https\:\/\/www\.nirsoft\.net\/utils\/.{0,1000}\.exe/ nocase ascii wide
                        $string5_nirsoft_tools_greyware_tool_keyword = /https\:\/\/www\.nirsoft\.net\/utils\/.{0,1000}\.zip/ nocase ascii wide

    condition:
        any of them
}