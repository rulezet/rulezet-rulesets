rule pinggy
{
    meta:
        description = "Detection patterns for the tool 'pinggy' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pinggy"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\sa\.pinggy\.io/ nocase ascii wide
                        $string2 = /\.a\.pinggy\.online/ nocase ascii wide
                        $string3 = /\.free\.pinggy\.online/ nocase ascii wide
                        $string4 = /\/a\.pinggy\.io/ nocase ascii wide
                        $string5 = /\@a\.pinggy\.io/ nocase ascii wide

    condition:
        any of them
}