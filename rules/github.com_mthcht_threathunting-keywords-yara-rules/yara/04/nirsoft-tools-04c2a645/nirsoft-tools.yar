rule nirsoft_tools
{
    meta:
        description = "Detection patterns for the tool 'nirsoft tools' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nirsoft tools"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /https\:\/\/www\.nirsoft\.net\/toolsdownload\// nocase ascii wide
                        $string2 = /https\:\/\/www\.nirsoft\.net\/toolsdownload\/.{0,1000}\.exe/ nocase ascii wide
                        $string3 = /https\:\/\/www\.nirsoft\.net\/toolsdownload\/.{0,1000}\.zip/ nocase ascii wide
                        $string4 = /https\:\/\/www\.nirsoft\.net\/utils\/.{0,1000}\.exe/ nocase ascii wide
                        $string5 = /https\:\/\/www\.nirsoft\.net\/utils\/.{0,1000}\.zip/ nocase ascii wide

    condition:
        any of them
}